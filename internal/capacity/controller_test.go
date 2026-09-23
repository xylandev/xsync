package capacity

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/xylandev/xsync/internal/config"
)

func testConfig() config.CapacityConfig {
	return config.CapacityConfig{
		SoftPercent: 75, HardPercent: 90, CriticalPercent: 95,
		TargetRunway: 30 * time.Minute, MinFreeBytes: 1 << 20,
	}
}

func TestWaitNAccountsBytesBeyondBurst(t *testing.T) {
	c := New(t.TempDir(), testConfig(), []config.Tenant{{ID: "t", Weight: 1}})
	const n = 10 << 20
	if n <= c.limiter.Burst() {
		t.Fatalf("test needs a write larger than the burst (%d)", c.limiter.Burst())
	}
	if err := c.WaitN(context.Background(), "t", n); err != nil {
		t.Fatal(err)
	}
	if got := c.uploaded.Load(); got != n {
		t.Fatalf("accounted %d bytes, want %d", got, n)
	}
}

// Truncating to one burst let the tail of a large write through for free: the
// first burst is pre-filled, so the call returned almost immediately.
func TestWaitNThrottlesWholeWriteNotJustFirstBurst(t *testing.T) {
	cfg := testConfig()
	cfg.MaxUploadBPS = 8 << 20
	c := New(t.TempDir(), cfg, []config.Tenant{{ID: "t", Weight: 1}})

	start := time.Now()
	if err := c.WaitN(context.Background(), "t", 12<<20); err != nil {
		t.Fatal(err)
	}
	if elapsed := time.Since(start); elapsed < 500*time.Millisecond {
		t.Fatalf("12 MiB at 8 MiB/s returned in %v; the limiter did not see the whole write", elapsed)
	}
}

func TestWaitNRejectsWhenCritical(t *testing.T) {
	c := New(t.TempDir(), testConfig(), []config.Tenant{{ID: "t", Weight: 1}})
	c.mu.Lock()
	c.snapshot.Critical = true
	c.mu.Unlock()
	if err := c.WaitN(context.Background(), "t", 1<<10); !errors.Is(err, ErrCriticalCapacity) {
		t.Fatalf("err = %v, want ErrCriticalCapacity", err)
	}
}

// A vanished client must not hold a tenant's concurrency slot forever, which is
// only true if the caller passes a cancellable context.
func TestAcquireUploadHonoursCancellation(t *testing.T) {
	c := New(t.TempDir(), testConfig(), []config.Tenant{{ID: "t", Weight: 1, MaxConcurrent: 2}})
	first, err := c.AcquireUpload(context.Background(), "t")
	if err != nil {
		t.Fatal(err)
	}
	second, err := c.AcquireUpload(context.Background(), "t")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err = c.AcquireUpload(ctx, "t"); !errors.Is(err, context.Canceled) {
		t.Fatalf("err = %v, want context.Canceled", err)
	}
	first()
	second()
	if _, err = c.AcquireUpload(context.Background(), "t"); err != nil {
		t.Fatalf("slot not released: %v", err)
	}
}
