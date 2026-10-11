//go:build unix

package policy

import (
	"os"

	"golang.org/x/sys/unix"
)

func publishImmutable(directory *os.File, temporary, final string, owner *resourceSession) error {
	// Link is an atomic non-replacing publication in the captured directory.
	// The temporary link is removed by the owner only after successful Close.
	return unix.Linkat(int(directory.Fd()), temporary, int(directory.Fd()), final, 0)
}
