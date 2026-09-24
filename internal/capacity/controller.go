package capacity

import (
	"context"
	"errors"
	"math"
	"sort"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/xylandev/xsync/internal/config"
	"golang.org/x/time/rate"
)

var (
	ErrCriticalCapacity = errors.New("critical storage capacity reached")
	ErrUploadsRejected  = errors.New("storage is above the hard watermark; new uploads are rejected")
	ErrTooManyUploads   = errors.New("too many concurrent uploads for this account")
)

// StatFS reports the total and available bytes of the filesystem holding path.
type StatFS func(path string) (total, avail uint64, err error)

func osStatFS(path string) (uint64, uint64, error) {
	var st syscall.Statfs_t
	if err := syscall.Statfs(path, &st); err != nil {
		return 0, 0, err
	}
	return uint64(st.Blocks) * uint64(st.Bsize), uint64(st.Bavail) * uint64(st.Bsize), nil
}

type Snapshot struct {
	TotalBytes     uint64
	AvailableBytes uint64
	ReservedBytes  uint64
	UsedPercent    float64
	UploadBPS      float64
	DownloadBPS    float64
	DeleteBPS      float64
	// UploadLimitBPS is the global upload budget; +Inf means unthrottled.
	UploadLimitBPS float64
	Throttled      bool
	RejectNew      bool
	Critical       bool
	StatErrors     uint64
	MeasuredAt     time.Time
	Tenants        map[string]TenantSnapshot
}

type TenantSnapshot struct {
	UploadBPS      float64
	UploadLimitBPS float64
	ActiveUploads  int
	SlotRejections uint64
}

type tenantState struct {
	limiter    *rate.Limiter
	weight     int
	max        int64
	sem        chan struct{}
	lastActive atomic.Int64
	bytes      atomic.Uint64
	lastBytes  uint64
	ewma       float64
	rejected   atomic.Uint64
}

type Controller struct {
	root   string
	cfg    config.CapacityConfig
	statfs StatFS
	now    func() time.Time
	global *rate.Limiter

	mu       sync.RWMutex
	snapshot Snapshot
	tenants  map[string]*tenantState

	reserved   atomic.Int64
	statErrors atomic.Uint64

	uploaded, downloaded, deleted         atomic.Uint64
	lastUploaded, lastDownloaded, lastDel uint64
	ewmaUpload, ewmaDownload, ewmaDelete  float64
	drainEstimate                         float64
	sampledOnce                           bool
	activityWindow                        time.Duration
	burst                                 int
}

const burst = 4 << 20

func New(root string, cfg config.CapacityConfig, tenants []config.Tenant) *Controller {
	return NewWithStatFS(root, cfg, tenants, osStatFS, time.Now)
}

// NewWithStatFS builds a controller with injectable filesystem and clock, so the
// control loop can be tested without filling a real disk.
func NewWithStatFS(root string, cfg config.CapacityConfig, tenants []config.Tenant, statfs StatFS, now func() time.Time) *Controller {
	limit := rate.Inf
	if cfg.MaxUploadBPS > 0 {
		limit = rate.Limit(cfg.MaxUploadBPS)
	}
	c := &Controller{root: root, cfg: cfg, statfs: statfs, now: now, global: rate.NewLimiter(limit, burst), tenants: map[string]*tenantState{}, activityWindow: 10 * time.Second, burst: burst}
	c.SyncTenants(tenants)
	return c
}

// SyncTenants applies an account list: new accounts get limiters, changed
// limits take effect, and removed accounts lose their state. Uploads holding a
// slot keep a reference to the old semaphore and release into it.
func (c *Controller) SyncTenants(list []config.Tenant) {
	c.mu.Lock()
	defer c.mu.Unlock()
	seen := map[string]bool{}
	for _, t := range list {
		seen[t.ID] = true
		w := t.Weight
		if w <= 0 {
			w = 1
		}
		maxConcurrent := t.MaxConcurrent
		if maxConcurrent <= 0 {
			maxConcurrent = 8
		}
		st := c.tenants[t.ID]
		if st == nil {
			st = &tenantState{limiter: rate.NewLimiter(rate.Inf, burst)}
			c.tenants[t.ID] = st
		}
		st.weight, st.max = w, t.MaxUploadBPS
		if st.max > 0 && st.limiter.Limit() == rate.Inf {
			st.limiter.SetLimit(rate.Limit(st.max))
		}
		if st.sem == nil || cap(st.sem) != maxConcurrent {
			st.sem = make(chan struct{}, maxConcurrent)
		}
	}
	for id := range c.tenants {
		if !seen[id] {
			delete(c.tenants, id)
		}
	}
}

func (c *Controller) Run(ctx context.Context) {
	t := time.NewTicker(time.Second)
	defer t.Stop()
	c.Sample()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			c.Sample()
		}
	}
}

func isInf(l rate.Limit) bool { return l == rate.Inf || math.IsInf(float64(l), 1) }

func (c *Controller) reserveFloor(total uint64) uint64 {
	floor := c.cfg.MinFreeBytes
	if criticalFree := uint64(float64(total) * (100 - c.cfg.CriticalPercent) / 100); criticalFree > floor {
		floor = criticalFree
	}
	return floor
}

// Sample takes one measurement and retunes the limiters. Run calls it every
// second; tests call it directly.
func (c *Controller) Sample() {
	total, avail, err := c.statfs(c.root)
	if err != nil {
		c.statErrors.Add(1)
		c.mu.Lock()
		// Without a measurement the safe assumption is that the disk is
		// critical: refusing uploads is recoverable, filling the disk is not.
		c.snapshot.Critical, c.snapshot.RejectNew = true, true
		c.snapshot.StatErrors = c.statErrors.Load()
		c.mu.Unlock()
		return
	}
	reserved := uint64(max(c.reserved.Load(), 0))
	effAvail := uint64(0)
	if avail > reserved {
		effAvail = avail - reserved
	}
	usedPct := 0.0
	if total > 0 {
		usedPct = 100 * float64(total-min(effAvail, total)) / float64(total)
	}
	u, d, del := c.uploaded.Load(), c.downloaded.Load(), c.deleted.Load()
	instantU, instantD, instantDel := float64(u-c.lastUploaded), float64(d-c.lastDownloaded), float64(del-c.lastDel)
	c.lastUploaded, c.lastDownloaded, c.lastDel = u, d, del
	// A short time constant for the rates shown in metrics, and a long one for
	// the drain estimate: deletions arrive in bursts (one whole file per
	// commit), and a budget that followed each burst would oscillate.
	const fast, slow = 0.3, 0.05
	if !c.sampledOnce {
		c.ewmaUpload, c.ewmaDownload, c.ewmaDelete, c.drainEstimate = instantU, instantD, instantDel, instantDel
		c.sampledOnce = true
	} else {
		c.ewmaUpload += fast * (instantU - c.ewmaUpload)
		c.ewmaDownload += fast * (instantD - c.ewmaDownload)
		c.ewmaDelete += fast * (instantDel - c.ewmaDelete)
		c.drainEstimate += slow * (instantDel - c.drainEstimate)
	}

	desired := math.Inf(1)
	if c.cfg.MaxUploadBPS > 0 {
		desired = float64(c.cfg.MaxUploadBPS)
	}
	throttled := false
	if usedPct >= c.cfg.SoftPercent {
		floor := c.reserveFloor(total)
		spare := 0.0
		if effAvail > floor {
			spare = float64(effAvail - floor)
		}
		// Only deletions free space; downloads that are not committed yet
		// do not, so they are not part of the drain estimate.
		budget := c.drainEstimate + spare/c.cfg.TargetRunway.Seconds()
		if budget < desired {
			desired = budget
			throttled = true
		}
	}
	critical := usedPct >= c.cfg.CriticalPercent || effAvail <= c.cfg.MinFreeBytes
	if critical {
		desired, throttled = 0, true
	}

	current := c.global.Limit()
	switch {
	case math.IsInf(desired, 1):
		c.global.SetLimit(rate.Inf)
	case isInf(current) || desired < float64(current):
		// Cut immediately: the budget exists to protect the disk.
		c.global.SetLimit(rate.Limit(math.Max(desired, 1)))
	default:
		// Recover gradually so a single burst of deletions does not open
		// the floodgates.
		c.global.SetLimit(rate.Limit(math.Max(1, math.Min(desired, float64(current)*1.25+float64(burst)))))
	}
	globalLimit := c.global.Limit()

	now := c.now()
	c.mu.Lock()
	activeWeight := 0
	for _, st := range c.tenants {
		if now.Sub(time.Unix(0, st.lastActive.Load())) < c.activityWindow || len(st.sem) > 0 {
			activeWeight += st.weight
		}
	}
	tenants := make(map[string]TenantSnapshot, len(c.tenants))
	for id, st := range c.tenants {
		b := st.bytes.Load()
		inst := float64(b - st.lastBytes)
		st.lastBytes = b
		st.ewma += fast * (inst - st.ewma)
		share := math.Inf(1)
		if !isInf(globalLimit) {
			// Work-conserving split: the budget is divided among accounts
			// that are actually uploading, so a lone active account is not
			// held to a share reserved for idle ones. An idle account is
			// sized as if it had just become active.
			weightPool := activeWeight
			if now.Sub(time.Unix(0, st.lastActive.Load())) >= c.activityWindow && len(st.sem) == 0 {
				weightPool += st.weight
			}
			if weightPool == 0 {
				weightPool = st.weight
			}
			share = float64(globalLimit) * float64(st.weight) / float64(weightPool)
		}
		if st.max > 0 && share > float64(st.max) {
			share = float64(st.max)
		}
		if math.IsInf(share, 1) {
			st.limiter.SetLimit(rate.Inf)
		} else {
			st.limiter.SetLimit(rate.Limit(math.Max(1, share)))
		}
		tenants[id] = TenantSnapshot{UploadBPS: st.ewma, UploadLimitBPS: share, ActiveUploads: len(st.sem), SlotRejections: st.rejected.Load()}
	}
	limitBPS := math.Inf(1)
	if !isInf(globalLimit) {
		limitBPS = float64(globalLimit)
	}
	c.snapshot = Snapshot{
		TotalBytes: total, AvailableBytes: avail, ReservedBytes: reserved, UsedPercent: usedPct,
		UploadBPS: c.ewmaUpload, DownloadBPS: c.ewmaDownload, DeleteBPS: c.ewmaDelete,
		UploadLimitBPS: limitBPS, Throttled: throttled,
		RejectNew: usedPct >= c.cfg.HardPercent || critical, Critical: critical,
		StatErrors: c.statErrors.Load(), MeasuredAt: now.UTC(), Tenants: tenants,
	}
	c.mu.Unlock()
}

func (c *Controller) Snapshot() Snapshot {
	c.mu.RLock()
	defer c.mu.RUnlock()
	s := c.snapshot
	return s
}

// AdmitUpload reports whether a new upload may start given the watermarks.
func (c *Controller) AdmitUpload() error {
	s := c.Snapshot()
	switch {
	case s.Critical:
		return ErrCriticalCapacity
	case s.RejectNew:
		return ErrUploadsRejected
	}
	return nil
}

// AllowNewUpload is AdmitUpload as a boolean.
func (c *Controller) AllowNewUpload() bool { return c.AdmitUpload() == nil }

// CheckCritical returns ErrCriticalCapacity while the disk is critical. Writes
// that are not rate limited (server-side copies) call it periodically.
func (c *Controller) CheckCritical() error {
	if c.Snapshot().Critical {
		return ErrCriticalCapacity
	}
	return nil
}

// Reserve claims n bytes of headroom above the critical floor for a server-side
// write whose size is known up front, such as a multipart assembly. Reserved
// bytes count as used until release is called, so concurrent reservations
// cannot all pass against the same free space.
func (c *Controller) Reserve(n int64) (func(), bool) {
	if n <= 0 {
		return func() {}, true
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	s := c.snapshot
	if s.Critical || s.RejectNew {
		return nil, false
	}
	if s.TotalBytes > 0 {
		reserved := uint64(max(c.reserved.Load(), 0))
		floor := c.reserveFloor(s.TotalBytes)
		if s.AvailableBytes < reserved+floor || s.AvailableBytes-reserved-floor < uint64(n) {
			return nil, false
		}
	}
	c.reserved.Add(n)
	var once sync.Once
	return func() { once.Do(func() { c.reserved.Add(-n) }) }, true
}

// AllowBytes reports whether n more bytes fit before the critical watermark.
func (c *Controller) AllowBytes(n int64) bool {
	release, ok := c.Reserve(n)
	if ok {
		release()
	}
	return ok
}

func (c *Controller) tenant(id string) *tenantState {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.tenants[id]
}

// AcquireUpload takes one of the tenant's concurrent-upload slots. It waits at
// most upload_slot_wait; blocking indefinitely would park protocol workers
// (SFTP processes opens sequentially per session) and deadlock the session.
func (c *Controller) AcquireUpload(ctx context.Context, tenant string) (func(), error) {
	st := c.tenant(tenant)
	if st == nil {
		return func() {}, nil
	}
	sem := st.sem
	release := func() func() {
		var once sync.Once
		return func() { once.Do(func() { <-sem }) }
	}
	select {
	case sem <- struct{}{}:
		return release(), nil
	default:
	}
	if c.cfg.UploadSlotWait <= 0 {
		st.rejected.Add(1)
		return nil, ErrTooManyUploads
	}
	timer := time.NewTimer(c.cfg.UploadSlotWait)
	defer timer.Stop()
	select {
	case sem <- struct{}{}:
		return release(), nil
	case <-timer.C:
		st.rejected.Add(1)
		return nil, ErrTooManyUploads
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

func (c *Controller) WaitN(ctx context.Context, tenant string, n int) error {
	if n <= 0 {
		return nil
	}
	if c.Snapshot().Critical {
		return ErrCriticalCapacity
	}
	st := c.tenant(tenant)
	// A single reservation cannot exceed the limiter's burst, so consume the
	// request in burst-sized chunks. Truncating instead would let the tail of a
	// large write bypass both the rate limit and the throughput accounting.
	chunk := c.burst
	for remaining := n; remaining > 0; {
		take := min(remaining, chunk)
		if err := c.global.WaitN(ctx, take); err != nil {
			return err
		}
		if st != nil {
			if err := st.limiter.WaitN(ctx, take); err != nil {
				return err
			}
			st.bytes.Add(uint64(take))
			st.lastActive.Store(c.now().UnixNano())
		}
		c.uploaded.Add(uint64(take))
		remaining -= take
	}
	return nil
}

func (c *Controller) ObserveDownload(n int64) {
	if n > 0 {
		c.downloaded.Add(uint64(n))
	}
}

func (c *Controller) ObserveDelete(n int64) {
	if n > 0 {
		c.deleted.Add(uint64(n))
	}
}

// TenantIDs returns the tenants the controller tracks, sorted.
func (c *Controller) TenantIDs() []string {
	c.mu.RLock()
	defer c.mu.RUnlock()
	out := make([]string, 0, len(c.tenants))
	for id := range c.tenants {
		out = append(out, id)
	}
	sort.Strings(out)
	return out
}
