package outbound

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/binary"
	"encoding/pem"
	"fmt"
	"io"
	"net"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/metacubex/http/httptest"
	"github.com/metacubex/mihomo/component/forwarding"
	ovpn "github.com/metacubex/mihomo/transport/openvpn"
	"github.com/metacubex/tls"
)

type openVPNTestUDP struct {
	net.PacketConn
	mu     sync.Mutex
	remote net.Addr
}

func (c *openVPNTestUDP) Read(b []byte) (int, error) {
	n, remote, err := c.ReadFrom(b)
	if err == nil {
		c.mu.Lock()
		c.remote = remote
		c.mu.Unlock()
	}
	return n, err
}
func (c *openVPNTestUDP) Write(b []byte) (int, error) { return c.WriteTo(b, c.RemoteAddr()) }
func (c *openVPNTestUDP) RemoteAddr() net.Addr        { c.mu.Lock(); defer c.mu.Unlock(); return c.remote }

// This peer reuses the upstream control, TLS and data codecs. It exercises a
// successful adapter handshake and encrypted packets, not a second VPN engine.
func openVPNSharedPeer(ctx context.Context, packetIO ovpn.PacketIO, certificate tls.Certificate, protocol string, received chan<- []byte) error {
	mux := ovpn.NewPacketMux(packetIO)
	stop := context.AfterFunc(ctx, func() { _ = mux.Close() })
	defer stop()
	defer mux.Close()
	go mux.Run()
	raw, err := mux.ReadPacket(ctx)
	if err != nil {
		return err
	}
	reset, _, _, err := ovpn.DecodeControlPacket(nil, raw)
	if err != nil {
		return err
	}
	var serverID ovpn.SessionID
	copy(serverID[:], "server01")
	control := ovpn.NewControlChannel(mux, nil, serverID)
	control.SetRemoteSessionID(reset.LocalSession)
	control.MarkReceived(reset.MessageID)
	control.QueueAck(reset.MessageID)
	if _, err = control.Send(ctx, ovpn.PControlHardResetServerV2, nil); err != nil {
		return err
	}
	conn := ovpn.NewControlConn(control)
	defer conn.Close()
	serverTLS := tls.Server(conn, &tls.Config{Certificates: []tls.Certificate{certificate}})
	if err = serverTLS.HandshakeContext(ctx); err != nil {
		return err
	}
	var fixed [117]byte // reserved + key-method + premaster + two randoms
	if _, err = io.ReadFull(serverTLS, fixed[:]); err != nil {
		return err
	}
	if fixed[4] != ovpn.KeyMethod2 {
		return fmt.Errorf("unexpected key method %d", fixed[4])
	}
	for i := 0; i < 4; i++ {
		var size [2]byte
		if _, err = io.ReadFull(serverTLS, size[:]); err != nil {
			return err
		}
		if _, err = io.CopyN(io.Discard, serverTLS, int64(binary.BigEndian.Uint16(size[:]))); err != nil {
			return err
		}
	}
	var sources ovpn.KeySource2
	copy(sources.Client.PreMaster[:], fixed[5:53])
	copy(sources.Client.Random1[:], fixed[53:85])
	copy(sources.Client.Random2[:], fixed[85:117])
	if _, err = rand.Read(sources.Server.Random1[:]); err != nil {
		return err
	}
	if _, err = rand.Read(sources.Server.Random2[:]); err != nil {
		return err
	}
	response := append(binary.BigEndian.AppendUint32(nil, 0), ovpn.KeyMethod2)
	response = append(response, sources.Server.Random1[:]...)
	response = append(response, sources.Server.Random2[:]...)
	for _, text := range []string{ovpn.InstallScriptOptionsString(protocol, ovpn.CipherAES128GCM, ovpn.AuthSHA256, ""), "", "", ""} {
		response = binary.BigEndian.AppendUint16(response, uint16(len(text)+1))
		response = append(response, text...)
		response = append(response, 0)
	}
	if _, err = serverTLS.Write(response); err != nil {
		return err
	}
	var request []byte
	for {
		var b [1]byte
		if _, err = io.ReadFull(serverTLS, b[:]); err != nil {
			return err
		}
		if b[0] == 0 {
			break
		}
		request = append(request, b[0])
	}
	if string(request) != ovpn.PushRequest {
		return fmt.Errorf("unexpected push request %q", request)
	}
	if _, err = serverTLS.Write([]byte("PUSH_REPLY,ifconfig 10.8.0.2 255.255.255.0,cipher AES-128-GCM,peer-id 0\x00")); err != nil {
		return err
	}
	keys, err := ovpn.DeriveClientKeyMaterial(sources, reset.LocalSession, serverID, 32)
	if err != nil {
		return err
	}
	keys.SendCipherKey, keys.RecvCipherKey = keys.RecvCipherKey[:16], keys.SendCipherKey[:16]
	keys.SendHMACKey, keys.RecvHMACKey = keys.RecvHMACKey, keys.SendHMACKey
	data, err := ovpn.NewDataChannel(keys, ovpn.CipherAES128GCM, ovpn.AuthSHA256, 0, 0)
	if err != nil {
		return err
	}
	for {
		raw, err := mux.ReadDataPacket(ctx)
		if err != nil {
			return err
		}
		plain, err := data.Decrypt(raw)
		if err != nil {
			return err
		}
		select {
		case received <- plain:
		case <-ctx.Done():
			return ctx.Err()
		}
	}
}

func TestSharedOpenVPNTransport(t *testing.T) {
	forwarding.Enable()
	for _, protocol := range []string{ovpn.ProtoTCP, ovpn.ProtoUDP} {
		for _, timeout := range []int{0, 2} {
			t.Run(fmt.Sprintf("%s/timeout=%d", protocol, timeout), func(t *testing.T) {
				certificate := httptest.NewTLSServer(nil)
				defer certificate.Close()
				ctx, stopServer := context.WithTimeout(context.Background(), 8*time.Second)
				defer stopServer()
				var address string
				var listener net.Listener
				var packetIO ovpn.PacketIO
				if protocol == ovpn.ProtoTCP {
					var err error
					listener, err = net.Listen("tcp", "127.0.0.1:0")
					if err != nil {
						t.Fatal(err)
					}
					defer listener.Close()
					address = listener.Addr().String()
				} else {
					packet, err := net.ListenPacket("udp", "127.0.0.1:0")
					if err != nil {
						t.Fatal(err)
					}
					defer packet.Close()
					address = packet.LocalAddr().String()
					packetIO = ovpn.NewDatagramPacketIO(&openVPNTestUDP{PacketConn: packet})
				}
				received := make(chan []byte, 8)
				serverDone := make(chan error, 1)
				go func() {
					if listener != nil {
						c, err := listener.Accept()
						if err != nil {
							serverDone <- err
							return
						}
						packetIO = ovpn.NewTCPPacketIO(c)
					}
					serverDone <- openVPNSharedPeer(ctx, packetIO, certificate.TLS.Certificates[0], protocol, received)
				}()
				addr := netip.MustParseAddrPort(address)
				d := &poolTestDialer{sockets: make(chan *poolTestSocket, 8)}
				client, err := NewOpenVPN(OpenVPNOption{BasicOption: BasicOption{DialerForAPI: d}, Server: addr.Addr().String(), Port: int(addr.Port()), Proto: protocol, CA: string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certificate.TLS.Certificates[0].Certificate[0]})), Username: "test", Cipher: ovpn.CipherAES128GCM, HandshakeTimeout: timeout})
				if err != nil {
					t.Fatal(err)
				}
				defer client.Close()
				guard := time.AfterFunc(5*time.Second, func() { _ = client.Close() })
				defer guard.Stop()
				requestCtx, cancel := context.WithCancel(context.Background())
				defer cancel()
				_, _, err = client.run(requestCtx)
				if err != nil {
					select {
					case peerErr := <-serverDone:
						t.Fatalf("handshake: %v; peer: %v", err, peerErr)
					default:
						t.Fatal(err)
					}
				}
				cancel()
				_ = client.runLock.Acquire(context.Background(), 1)
				protocolClient := client.client
				client.runLock.Release(1)
				if protocolClient == nil {
					t.Fatal("shared OpenVPN client stopped after handshake")
				}
				for i := 0; i < 2; i++ {
					payload := []byte{0x45, 0, 0, 20, 0, 0, 0, 0, 64, 1, 0, 0, 10, 8, 0, 2, 10, 8, 0, 1}
					if err = protocolClient.WriteIPPacket(context.Background(), payload); err != nil {
						t.Fatal(err)
					}
					select {
					case plain := <-received:
						if !bytes.Equal(plain, payload) {
							t.Fatalf("decrypted packet = %x", plain)
						}
					case err := <-serverDone:
						t.Fatal(err)
					case <-time.After(3 * time.Second):
						t.Fatal("encrypted packet not received after handshake context ended")
					}
				}
				if err = client.Close(); err != nil {
					t.Fatal(err)
				}
				poolTestClosed(t, d)
				stopServer()
				select {
				case <-serverDone:
				case <-time.After(3 * time.Second):
					t.Fatal("test peer did not stop")
				}
			})
		}
	}
}
