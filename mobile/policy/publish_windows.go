package policy

import (
	"errors"
	"os"
	"unsafe"

	"golang.org/x/sys/windows"
)

func publishImmutable(directory *os.File, temporary, final string, owner *resourceSession) (result error) {
	name, err := windows.NewNTUnicodeString(temporary)
	if err != nil {
		return err
	}
	attributes := windows.OBJECT_ATTRIBUTES{RootDirectory: windows.Handle(directory.Fd()), ObjectName: name}
	attributes.Length = uint32(unsafe.Sizeof(attributes))
	var ioStatus windows.IO_STATUS_BLOCK
	var handle windows.Handle
	err = windows.NtCreateFile(&handle, windows.FILE_GENERIC_READ|windows.FILE_GENERIC_WRITE|windows.DELETE, &attributes, &ioStatus, nil, 0, windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE, windows.FILE_OPEN, windows.FILE_NON_DIRECTORY_FILE|windows.FILE_OPEN_REPARSE_POINT, 0, 0)
	if err != nil {
		return err
	}
	file := os.NewFile(uintptr(handle), temporary)
	defer func() {
		closeErr := file.Close()
		owner.RetainWorkerCloseFailure(file, closeErr)
		result = errors.Join(result, closeErr)
	}()
	// A basename and null target root rename within this captured source file's
	// parent. The source was opened relative to the already captured directory.
	type renameInformation struct {
		Replace uint32
		Root    windows.Handle
		Length  uint32
		Name    [1]uint16
	}
	utf16, err := windows.UTF16FromString(final)
	if err != nil {
		return err
	}
	length := (len(utf16) - 1) * 2
	buffer := make([]byte, int(unsafe.Offsetof(renameInformation{}.Name))+length)
	info := (*renameInformation)(unsafe.Pointer(&buffer[0]))
	info.Length = uint32(length)
	copy(unsafe.Slice(&info.Name[0], len(utf16)-1), utf16[:len(utf16)-1])
	err = windows.NtSetInformationFile(handle, &ioStatus, &buffer[0], uint32(len(buffer)), windows.FileRenameInformation)
	if errors.Is(err, windows.STATUS_OBJECT_NAME_COLLISION) {
		return os.ErrExist
	}
	return err
}
