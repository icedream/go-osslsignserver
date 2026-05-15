package signing

import (
	"errors"
	"os"
	"syscall"
)

var (
	ErrNotTmpfs = errors.New("work directory is not on tmpfs")
)

// TMPFS_MAGIC is the filesystem type magic number for tmpfs.
const TMPFS_MAGIC = 0x01021994

// EnsureWorkDirExists creates the work directory if it doesn't exist.
func EnsureWorkDirExists(path string) error {
	return os.MkdirAll(path, 0700)
}

// VerifyTmpfs checks that the given path is on a tmpfs filesystem.
func VerifyTmpfs(path string) error {
	var stat syscall.Statfs_t
	if err := syscall.Statfs(path, &stat); err != nil {
		return err
	}
	if stat.Type != TMPFS_MAGIC {
		return ErrNotTmpfs
	}
	return nil
}
