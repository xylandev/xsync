package capacity

import (
	"context"
	"errors"
	"math"
	"sync"
	"testing"
	"time"

	"github.com/xylandev/xsync/internal/config"
)

func testConfig() config.CapacityConfig {
	cfg := config.Default().Capacity
	cfg.MinFreeBytes = 0
	cfg.UploadSlotWait = 50 * time.Millisecond
	return cfg
}

type fakeDisk struct {
	mu           sync.Mutex
	total, avail uint64
	err          error
}

func (d *fakeDisk) statfs(string) (uint64, uint64, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.total, d.avail, d.err
}

func (d *fakeDisk) set(avail uint64) {
	d.mu.Lock()
	d.avail = avail
	d.mu.Unlock()
}

const gib = 1 << 30

func newTestController(t *testing.T, disk *fakeDisk, tenants []config.Tenant) *Controller {
	t.Helper()
	c := NewWithStatFS("/", testConfig(), tenants, disk.statfs, time.Now)
	c.Sample()
	return c
}

func TestWaitNAccountsBytesBeyondBurst(t *testing.T) {
	disk := &fakeDisk{total: 100 * gib, avail: 90 * gib}
	c := newTestController(t, disk, []config.Tenant{{ID: "t"}})
	if err := c.WaitN(context.Background(), "t", 3*burst+17); err != nil {
		t.Fatal(err)
	}
	if got := c.uploaded.Load(); got != uint64(3*burst+17) {
		t.Fatalf("accounted %d bytes, want %d", got, 3*burst+17)
	}
}

func TestWaitNRejectsWhenCritical(t *testing.T) {
	disk := &fakeDisk{total: 100 * gib, avail: 1 * gib}
	c := newTestController(t, disk, nil)
	if err := c.WaitN(context.Background(), "t", 10); !errors.Is(err, ErrCriticalCapacity) {
		t.Fatalf("err = %v, want critical", err)
	}
	if err := c.AdmitUpload(); !errors.Is(err, ErrCriticalCapacity) {
		t.Fatalf("admit = %v, want critical", err)
	}
}

// rate.Inf is math.MaxFloat64, not +Inf. Treating it as a finite current limit
// made the controller shave 10% per second off 1.8e308 and take hours to
// reach the budget. Entering the soft zone must apply the budget at once.
func TestEnteringSoftZoneAppliesBudgetImmediately(t *testing.T) {
	disk := &fakeDisk{total: 100 * gib, avail: 50 * gib}
	c := newTestController(t, disk, []config.Tenant{{ID: "a"}})
	if s := c.Snapshot(); !math.IsInf(s.UploadLimitBPS, 1) || s.Throttled {
		t.Fatalf("below soft watermark: limit=%v throttled=%v, want unthrottled", s.UploadLimitBPS, s.Throttled)
	}
	disk.set(20 * gib) // 80% used
	c.Sample()
	s := c.Snapshot()
	// spare = 20GiB - 5GiB(critical floor) over a 30 minute runway.
	want := float64(15*gib) / (30 * 60)
	if !s.Throttled || math.Abs(s.UploadLimitBPS-want) > want*0.01 {
		t.Fatalf("limit = %v, want about %v after one sample", s.UploadLimitBPS, want)
	}
	if got := s.Tenants["a"].UploadLimitBPS; math.Abs(got-want) > want*0.01 {
		t.Fatalf("tenant limit = %v, want the whole budget for the only account", got)
	}
	disk.set(60 * gib)
	c.Sample()
	if s := c.Snapshot(); !math.IsInf(s.UploadLimitBPS, 1) {
		t.Fatalf("limit after recovery = %v, want unthrottled", s.UploadLimitBPS)
	}
}

// Budget shares must go to accounts that are uploading, not be reserved for
// idle ones.
func TestTenantSharesAreWorkConserving(t *testing.T) {
	disk := &fakeDisk{total: 100 * gib, avail: 20 * gib}
	tenants := []config.Tenant{{ID: "busy"}, {ID: "idle1"}, {ID: "idle2"}, {ID: "idle3"}}
	c := newTestController(t, disk, tenants)
	if err := c.WaitN(context.Background(), "busy", 1); err != nil {
		t.Fatal(err)
	}
	c.Sample()
	s := c.Snapshot()
	if got := s.Tenants["busy"].UploadLimitBPS; math.Abs(got-s.UploadLimitBPS) > 1 {
		t.Fatalf("busy share = %v, want the whole budget %v", got, s.UploadLimitBPS)
	}
	if got := s.Tenants["idle1"].UploadLimitBPS; math.Abs(got-s.UploadLimitBPS/2) > 1 {
		t.Fatalf("idle share = %v, want half the budget once it starts", got)
	}
}

func TestStatfsFailureFailsSafe(t *testing.T) {
	disk := &fakeDisk{total: 100 * gib, avail: 90 * gib}
	c := newTestController(t, disk, nil)
	disk.mu.Lock()
	disk.err = errors.New("EIO")
	disk.mu.Unlock()
	c.Sample()
	if err := c.AdmitUpload(); err == nil {
		t.Fatal("uploads admitted without a disk measurement")
	}
	if c.Snapshot().StatErrors != 1 {
		t.Fatal("stat error not counted")
	}
}

// Concurrent multipart completions used to pass the same free-space check and
// jointly write past the critical floor.
func TestReservationsAreCumulative(t *testing.T) {
	disk := &fakeDisk{total: 100 * gib, avail: 20 * gib}
	c := newTestController(t, disk, nil)
	// Floor is 5GiB, so 15GiB of headroom.
	r1, ok := c.Reserve(10 * gib)
	if !ok {
		t.Fatal("first reservation refused")
	}
	if _, ok := c.Reserve(10 * gib); ok {
		t.Fatal("second reservation granted against space already promised")
	}
	r1()
	r2, ok := c.Reserve(10 * gib)
	if !ok {
		t.Fatal("reservation refused after release")
	}
	r2()
}

func TestAcquireUploadFailsFastWhenSlotsAreBusy(t *testing.T) {
	disk := &fakeDisk{total: 100 * gib, avail: 90 * gib}
	c := newTestController(t, disk, []config.Tenant{{ID: "t", MaxConcurrent: 1}})
	release, err := c.AcquireUpload(context.Background(), "t")
	if err != nil {
		t.Fatal(err)
	}
	start := time.Now()
	if _, err = c.AcquireUpload(context.Background(), "t"); !errors.Is(err, ErrTooManyUploads) {
		t.Fatalf("err = %v, want ErrTooManyUploads", err)
	}
	if time.Since(start) > time.Second {
		t.Fatal("slot wait not bounded")
	}
	release()
	release() // releasing twice must not free a slot someone else holds
	r2, err := c.AcquireUpload(context.Background(), "t")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err = c.AcquireUpload(ctx, "t"); err == nil {
		t.Fatal("acquire ignored cancellation")
	}
	r2()
}

func TestSyncTenantsAppliesChanges(t *testing.T) {
	disk := &fakeDisk{total: 100 * gib, avail: 90 * gib}
	c := newTestController(t, disk, []config.Tenant{{ID: "a", MaxConcurrent: 1}})
	c.SyncTenants([]config.Tenant{{ID: "a", MaxConcurrent: 2}, {ID: "b"}})
	if ids := c.TenantIDs(); len(ids) != 2 {
		t.Fatalf("tenants = %v", ids)
	}
	r1, err := c.AcquireUpload(context.Background(), "a")
	if err != nil {
		t.Fatal(err)
	}
	r2, err := c.AcquireUpload(context.Background(), "a")
	if err != nil {
		t.Fatalf("raised max_concurrent not applied: %v", err)
	}
	r1()
	r2()
	c.SyncTenants([]config.Tenant{{ID: "b"}})
	if ids := c.TenantIDs(); len(ids) != 1 || ids[0] != "b" {
		t.Fatalf("removed tenant still tracked: %v", ids)
	}
}
