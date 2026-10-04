package listener

import (
	"errors"
	"io"
	"sort"
	"sync"

	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/listener/internal/lifecycle"
	"github.com/metacubex/mihomo/log"
)

func logListenerError(name string, err *error) {
	if *err != nil {
		log.Errorln("Update %s listener error: %s", name, *err)
	}
}

// Already-closed sockets satisfy the stop contract. Other close failures must
// reach the caller, including failures while rolling back a partial start.
func closeError(closer io.Closer) error {
	return lifecycle.Close(closer)
}

// ReCreate calls use the address of their global slot as key. A failed Close
// removes readiness, but keeps ownership here until a later call closes it.
var pendingListenerCloses sync.Map // key -> io.Closer

func closeRetired(key any, closer io.Closer) error {
	if err := closeError(closer); err != nil {
		pendingListenerCloses.Store(key, closer)
		return err
	}
	pendingListenerCloses.Delete(key)
	return nil
}

func closeAndClear[T interface {
	io.Closer
	comparable
}](slot *T) error {
	if old, ok := pendingListenerCloses.Load(slot); ok {
		if err := closeRetired(slot, old.(io.Closer)); err != nil {
			return err
		}
	}
	var zero T
	if *slot == zero {
		return nil
	}
	old := *slot
	*slot = zero
	return closeRetired(slot, old)
}

// The pair is either fully registered or absent. A partial previous pair is
// discarded, and a failed UDP bind also closes the new TCP socket. Replacing a
// listener does not restore the previous address when the new bind fails.
func recreatePair[T interface {
	C.Listener
	comparable
}, U interface {
	C.Listener
	comparable
}](tcp *T, udp *U, addr string, newTCP func() (T, error), newUDP func() (U, error)) error {
	var zeroTCP T
	var zeroUDP U
	if *tcp != zeroTCP && *udp != zeroUDP && (*tcp).RawAddress() == addr && (*udp).RawAddress() == addr {
		return nil
	}
	if err := errors.Join(closeAndClear(tcp), closeAndClear(udp)); err != nil {
		return err
	}
	if portIsZero(addr) {
		return nil
	}
	nextTCP, err := newTCP()
	if err != nil {
		return err
	}
	nextUDP, err := newUDP()
	if err != nil {
		*tcp = nextTCP
		return errors.Join(err, closeAndClear(tcp))
	}
	*tcp, *udp = nextTCP, nextUDP
	return nil
}

func sortedKeys[V any](m map[string]V) []string {
	keys := make([]string, 0, len(m))
	for key := range m {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}
