// Package platform checks the data directory before the server writes to it.
package platform

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
)

// VolumeMarker is the file init writes into the data directory. Its content
// must match data_volume_id in the configuration.
const VolumeMarker = ".xsync-volume"

// DataDirReport describes the data directory at startup.
type DataDirReport struct {
	FreeBytes uint64
	// LowSpace means free space is below min_free_bytes. The server still
	// starts, so downloads can drain the disk, but refuses uploads.
	LowSpace bool
	// Warnings are conditions worth logging that do not prevent startup.
	Warnings []string
}

// CheckDataDir verifies that path is the intended, writable data volume.
//
// The volume marker is the reliable check: inside a container a bind mount
// always looks like a separate mount point, even when the host path it came
// from is an empty directory on the system disk because the real volume
// failed to mount. A missing or different marker refuses startup, so the
// server never writes a fresh catalog next to the operating system.
func CheckDataDir(path string, requireMount bool, volumeID string, minFree uint64) (DataDirReport, error) {
	var report DataDirReport
	info, err := os.Stat(path)
	if err != nil {
		return report, fmt.Errorf("data directory: %w", err)
	}
	if !info.IsDir() {
		return report, fmt.Errorf("data directory is not a directory: %s", path)
	}
	marker, markerErr := os.ReadFile(filepath.Join(path, VolumeMarker))
	switch {
	case volumeID != "" && markerErr != nil:
		return report, fmt.Errorf("data directory %s has no %s marker: the data volume is probably not mounted", path, VolumeMarker)
	case volumeID != "" && strings.TrimSpace(string(marker)) != volumeID:
		return report, fmt.Errorf("data directory %s belongs to volume %q, configuration expects %q", path, strings.TrimSpace(string(marker)), volumeID)
	case volumeID == "":
		report.Warnings = append(report.Warnings, "data_volume_id is not set; run 'xsync-server volume adopt' so a missing mount is detected")
	}
	test := filepath.Join(path, ".xsync-write-test")
	f, err := os.OpenFile(test, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil && !errors.Is(err, os.ErrExist) {
		return report, fmt.Errorf("data directory is not writable: %w", err)
	}
	if f != nil {
		_ = f.Close()
	}
	_ = os.Remove(test)
	if requireMount && filepath.Clean(path) != string(filepath.Separator) {
		parent, err := os.Stat(filepath.Dir(filepath.Clean(path)))
		if err != nil {
			return report, err
		}
		st, ok1 := info.Sys().(*syscall.Stat_t)
		pst, ok2 := parent.Sys().(*syscall.Stat_t)
		if !ok1 || !ok2 || st.Dev == pst.Dev {
			return report, fmt.Errorf("data directory is not a mount point: %s", path)
		}
	}
	var stat syscall.Statfs_t
	if err := syscall.Statfs(path, &stat); err != nil {
		return report, fmt.Errorf("statfs: %w", err)
	}
	report.FreeBytes = uint64(stat.Bavail) * uint64(stat.Bsize)
	if report.FreeBytes < minFree {
		report.LowSpace = true
		report.Warnings = append(report.Warnings, fmt.Sprintf("data directory has %d free bytes, below min_free_bytes %d: starting in drain-only mode (uploads refused, downloads served)", report.FreeBytes, minFree))
	}
	return report, nil
}

// WriteVolumeMarker records id as the identity of the data volume at path.
func WriteVolumeMarker(path, id string) error {
	name := filepath.Join(path, VolumeMarker)
	if raw, err := os.ReadFile(name); err == nil {
		if existing := strings.TrimSpace(string(raw)); existing != id {
			return fmt.Errorf("data directory already belongs to volume %q", existing)
		}
		return nil
	}
	return os.WriteFile(name, []byte(id+"\n"), 0o600)
}

// ReadVolumeMarker returns the volume ID recorded at path.
func ReadVolumeMarker(path string) (string, error) {
	raw, err := os.ReadFile(filepath.Join(path, VolumeMarker))
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(raw)), nil
}
