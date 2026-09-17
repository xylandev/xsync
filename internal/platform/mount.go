package platform

import (
	"fmt"
	"os"
	"path/filepath"
	"syscall"
)

func ValidateDataDir(path string, requireMount bool, minFree uint64) error {
	info, err := os.Stat(path)
	if err != nil {
		return fmt.Errorf("data directory: %w", err)
	}
	if !info.IsDir() {
		return fmt.Errorf("data directory is not a directory: %s", path)
	}
	test := filepath.Join(path, ".xsync-write-test")
	f, err := os.OpenFile(test, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return fmt.Errorf("data directory is not writable: %w", err)
	}
	_ = f.Close()
	_ = os.Remove(test)
	if requireMount && filepath.Clean(path) != string(filepath.Separator) {
		parent, err := os.Stat(filepath.Dir(filepath.Clean(path)))
		if err != nil {
			return err
		}
		st, ok1 := info.Sys().(*syscall.Stat_t)
		pst, ok2 := parent.Sys().(*syscall.Stat_t)
		if !ok1 || !ok2 || st.Dev == pst.Dev {
			return fmt.Errorf("data directory is not a mount point: %s", path)
		}
	}
	var stat syscall.Statfs_t
	if err := syscall.Statfs(path, &stat); err != nil {
		return fmt.Errorf("statfs: %w", err)
	}
	free := uint64(stat.Bavail) * uint64(stat.Bsize)
	if free < minFree {
		return fmt.Errorf("data directory has %d free bytes, need at least %d", free, minFree)
	}
	return nil
}
