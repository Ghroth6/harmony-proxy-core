package resolver

import (
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"time"

	"github.com/metacubex/mihomo/common/pool"

	D "github.com/miekg/dns"
)

const DefaultDnsReadTimeout = time.Second * 10
const DefaultDnsRelayTimeout = time.Second * 5

const SafeDnsPacketSize = 2 * 1024 // safe size which is 1232 from https://dnsflagday.net/2020/, so 2048 is enough

// RequestUDPSize returns the UDP payload size a reply to msg may occupy:
// the client's advertised EDNS0 buffer size, or 512 (D.MinMsgSize) without an OPT record.
func RequestUDPSize(msg *D.Msg) int {
	if opt := msg.IsEdns0(); opt != nil {
		return int(opt.UDPSize())
	}
	return D.MinMsgSize
}

func RelayDnsConn(ctx context.Context, conn net.Conn, readTimeout time.Duration) error {
	return relayDnsConn(ctx, conn, readTimeout, nil, false, false)
}

func relayDnsConn(ctx context.Context, conn net.Conn, readTimeout time.Duration, service Service, strict, replyFailure bool) (result error) {
	buff := pool.Get(pool.UDPBufferSize)
	defer func() {
		_ = pool.Put(buff)
		closeErr := conn.Close()
		if strict {
			result = errors.Join(result, closeErr)
		}
	}()
	for {
		if readTimeout > 0 {
			_ = conn.SetReadDeadline(time.Now().Add(readTimeout))
		}

		length := uint16(0)
		if err := binary.Read(conn, binary.BigEndian, &length); err != nil {
			if strict && ctx.Err() != nil {
				return ctx.Err()
			}
			if strict && !errors.Is(err, io.EOF) {
				return err
			}
			break
		}

		if int(length) > len(buff) {
			if strict {
				return errors.New("DNS packet exceeds relay bound")
			}
			break
		}

		n, err := io.ReadFull(conn, buff[:length])
		if err != nil {
			if strict && ctx.Err() != nil {
				return ctx.Err()
			}
			if strict {
				return err
			}
			break
		}

		err = func() error {
			queryCtx, cancel := context.WithTimeout(ctx, DefaultDnsRelayTimeout)
			defer cancel()
			inData := buff[:n]
			outBuff := buff[2:]
			msg, err := relayDnsPacketWithService(queryCtx, inData, outBuff, 0, service, strict)
			if err != nil && replyFailure {
				msg, err = dnsFailureResponse(ctx, inData, outBuff, err)
			}
			if err != nil {
				return err
			}

			if &msg[0] == &outBuff[0] { // msg is still in the buff
				binary.BigEndian.PutUint16(buff[:2], uint16(len(msg)))
				outBuff = buff[:2+len(msg)]
			} else { // buff not big enough (WTF???)
				newBuff := pool.Get(len(msg) + 2)
				defer pool.Put(newBuff)
				binary.BigEndian.PutUint16(newBuff[:2], uint16(len(msg)))
				copy(newBuff[2:], msg)
				outBuff = newBuff
			}

			_, err = conn.Write(outBuff)
			if err != nil {
				return err
			}
			return nil
		}()
		if err != nil {
			return err
		}
	}
	return nil
}

func relayDnsPacket(ctx context.Context, payload []byte, target []byte, maxSize int) ([]byte, error) {
	return relayDnsPacketWithService(ctx, payload, target, maxSize, nil, false)
}

func relayDnsPacketWithService(ctx context.Context, payload []byte, target []byte, maxSize int, service Service, strict bool) ([]byte, error) {
	if strict && ctx.Err() != nil {
		return nil, ctx.Err()
	}
	msg := &D.Msg{}
	if err := msg.Unpack(payload); err != nil {
		return nil, err
	}

	var r *D.Msg
	var err error
	if strict {
		if service == nil {
			return nil, ErrIPNotFound
		}
		r, err = service.ServeMsg(ctx, msg)
	} else {
		r, err = ServeMsg(ctx, msg)
	}
	if err != nil {
		if strict {
			return nil, err
		}
		m := new(D.Msg)
		m.SetRcode(msg, D.RcodeServerFailure)
		return m.PackBuffer(target)
	}
	if strict && ctx.Err() != nil {
		return nil, ctx.Err()
	}

	r.SetRcode(msg, r.Rcode)
	if maxSize > 0 { // udp
		if size := RequestUDPSize(msg); size < maxSize {
			maxSize = size
		}
		r.Truncate(maxSize)
	}
	r.Compress = true
	data, err := r.PackBuffer(target)
	if err != nil {
		return nil, err
	}
	// PackBuffer sizes its scratch space by the *uncompressed* message length and may
	// have allocated a new slice even though the compressed result fits into target.
	// Callers (e.g. the tun dns hijack) assume the result is backed by target, so copy it back.
	if len(data) > 0 && len(data) <= len(target) && &data[0] != &target[0] {
		data = target[:copy(target, data)]
	}
	return data, nil
}

// RelayDnsPacket will truncate udp message up to SafeDnsPacketSize
func RelayDnsPacket(ctx context.Context, payload []byte, target []byte) ([]byte, error) {
	return relayDnsPacket(ctx, payload, target, SafeDnsPacketSize)
}

// Captured mobile entry points bind one service for the entire operation.
func RelayDnsPacketWithService(ctx context.Context, payload []byte, target []byte, service Service) ([]byte, error) {
	bound := SafeDnsPacketSize
	if len(target) < bound {
		bound = len(target)
	}
	if bound < D.MinMsgSize {
		return nil, errors.New("DNS target is below packet bound")
	}
	return relayDnsPacketWithService(ctx, payload, target, bound, service, true)
}
func RelayDnsConnWithService(ctx context.Context, conn net.Conn, readTimeout time.Duration, service Service) error {
	return relayDnsConn(ctx, conn, readTimeout, service, true, false)
}

// DNS proxies retain upstream SERVFAIL replies for ordinary query failures while
// capturing one service. Association cancellation remains terminal, including
// when a single query's deadline has expired before its active association.
func RelayDnsProxyConn(ctx context.Context, conn net.Conn, readTimeout time.Duration, service Service) error {
	return relayDnsConn(ctx, conn, readTimeout, service, true, true)
}

func RelayDnsProxyPacket(ctx context.Context, payload []byte, target []byte, service Service) ([]byte, error) {
	queryCtx, cancel := context.WithTimeout(ctx, DefaultDnsRelayTimeout)
	defer cancel()
	reply, err := RelayDnsPacketWithService(queryCtx, payload, target, service)
	if err != nil {
		return dnsFailureResponse(ctx, payload, target, err)
	}
	return reply, nil
}

func dnsFailureResponse(ctx context.Context, payload, target []byte, cause error) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if errors.Is(cause, context.Canceled) {
		return nil, cause
	}
	request := new(D.Msg)
	if err := request.Unpack(payload); err != nil {
		return nil, cause
	}
	reply := new(D.Msg)
	reply.SetRcode(request, D.RcodeServerFailure)
	return reply.PackBuffer(target)
}
