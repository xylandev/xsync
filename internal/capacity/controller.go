package capacity

import (
	"context"
	"errors"
	"math"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/xylandev/xsync/internal/config"
	"golang.org/x/time/rate"
)

var ErrCriticalCapacity = errors.New("critical storage capacity reached")

type Snapshot struct {
	TotalBytes     uint64
	AvailableBytes uint64
	UsedPercent    float64
	UploadBPS      float64
	DownloadBPS    float64
	DeleteBPS      float64
	UploadLimitBPS float64
	RejectNew      bool
	Critical       bool
	MeasuredAt     time.Time
}

type Controller struct {
	root    string
	cfg     config.CapacityConfig
	limiter *rate.Limiter

	mu          sync.RWMutex
	snapshot    Snapshot
	tenants     map[string]*rate.Limiter
	weights     map[string]int
	tenantMax   map[string]int64
	semaphores  map[string]chan struct{}
	totalWeight int

	uploaded       atomic.Uint64
	downloaded     atomic.Uint64
	deleted        atomic.Uint64
	lastUploaded   uint64
	lastDownloaded uint64
	lastDeleted    uint64
	ewmaUpload     float64
	ewmaDownload   float64
	ewmaDelete     float64
}

func New(root string, cfg config.CapacityConfig, tenants []config.Tenant) *Controller {
	max := rate.Inf
	burst := 4 << 20
	if cfg.MaxUploadBPS > 0 {
		max = rate.Limit(cfg.MaxUploadBPS)
	}
	c := &Controller{root: root, cfg: cfg, limiter: rate.NewLimiter(max, burst), tenants: map[string]*rate.Limiter{}, weights: map[string]int{}, tenantMax: map[string]int64{}, semaphores: map[string]chan struct{}{}}
	for _, t := range tenants {
		limit := rate.Inf
		if t.MaxUploadBPS > 0 {
			limit = rate.Limit(t.MaxUploadBPS)
		}
		c.tenants[t.ID] = rate.NewLimiter(limit, burst)
		w := t.Weight
		if w <= 0 {
			w = 1
		}
		c.weights[t.ID] = w
		c.totalWeight += w
		c.tenantMax[t.ID] = t.MaxUploadBPS
		maxConcurrent := t.MaxConcurrent
		if maxConcurrent <= 0 {
			maxConcurrent = 8
		}
		c.semaphores[t.ID] = make(chan struct{}, maxConcurrent)
	}
	return c
}

func (c *Controller) Run(ctx context.Context) {
	t := time.NewTicker(time.Second)
	defer t.Stop()
	c.sample()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			c.sample()
		}
	}
}

func (c *Controller) sample() {
	var st syscall.Statfs_t
	if syscall.Statfs(c.root, &st) != nil {
		return
	}
	total := uint64(st.Blocks) * uint64(st.Bsize)
	avail := uint64(st.Bavail) * uint64(st.Bsize)
	usedPct := 0.0
	if total > 0 {
		usedPct = 100 * float64(total-avail) / float64(total)
	}
	u, d, del := c.uploaded.Load(), c.downloaded.Load(), c.deleted.Load()
	instantU, instantD, instantDel := float64(u-c.lastUploaded), float64(d-c.lastDownloaded), float64(del-c.lastDeleted)
	c.lastUploaded, c.lastDownloaded, c.lastDeleted = u, d, del
	const alpha = 0.18
	c.ewmaUpload += alpha * (instantU - c.ewmaUpload)
	c.ewmaDownload += alpha * (instantD - c.ewmaDownload)
	c.ewmaDelete += alpha * (instantDel - c.ewmaDelete)

	desired := math.Inf(1)
	if c.cfg.MaxUploadBPS > 0 {
		desired = float64(c.cfg.MaxUploadBPS)
	}
	if usedPct >= c.cfg.SoftPercent {
		reserve := c.cfg.MinFreeBytes
		criticalFree := uint64(float64(total) * (100 - c.cfg.CriticalPercent) / 100)
		if criticalFree > reserve {
			reserve = criticalFree
		}
		spare := float64(0)
		if avail > reserve {
			spare = float64(avail - reserve)
		}
		drain := math.Max(c.ewmaDownload, c.ewmaDelete)
		budget := drain + spare/c.cfg.TargetRunway.Seconds()
		if desired > budget {
			desired = budget
		}
	}
	if usedPct >= c.cfg.CriticalPercent || avail <= c.cfg.MinFreeBytes {
		desired = 1
	}
	current := float64(c.limiter.Limit())
	if math.IsInf(current, 1) {
		current = desired
	}
	if !math.IsInf(desired, 1) {
		low, high := current*0.9, current*1.1
		if current <= 1 {
			low, high = 1, math.Max(1, desired)
		}
		desired = math.Max(low, math.Min(high, desired))
		c.limiter.SetLimit(rate.Limit(math.Max(1, desired)))
	} else if c.cfg.MaxUploadBPS <= 0 && usedPct < c.cfg.SoftPercent {
		c.limiter.SetLimit(rate.Inf)
	}
	c.mu.Lock()
	for id, lim := range c.tenants {
		tenantDesired := math.Inf(1)
		if usedPct >= c.cfg.SoftPercent && c.totalWeight > 0 && !math.IsInf(desired, 1) {
			tenantDesired = desired * float64(c.weights[id]) / float64(c.totalWeight)
		}
		if max := c.tenantMax[id]; max > 0 && (math.IsInf(tenantDesired, 1) || tenantDesired > float64(max)) {
			tenantDesired = float64(max)
		}
		if math.IsInf(tenantDesired, 1) {
			lim.SetLimit(rate.Inf)
		} else {
			lim.SetLimit(rate.Limit(math.Max(1, tenantDesired)))
		}
	}
	c.snapshot = Snapshot{TotalBytes: total, AvailableBytes: avail, UsedPercent: usedPct, UploadBPS: c.ewmaUpload, DownloadBPS: c.ewmaDownload, DeleteBPS: c.ewmaDelete, UploadLimitBPS: float64(c.limiter.Limit()), RejectNew: usedPct >= c.cfg.HardPercent, Critical: usedPct >= c.cfg.CriticalPercent || avail <= c.cfg.MinFreeBytes, MeasuredAt: time.Now().UTC()}
	c.mu.Unlock()
}

func (c *Controller) Snapshot() Snapshot   { c.mu.RLock(); defer c.mu.RUnlock(); return c.snapshot }
func (c *Controller) AllowNewUpload() bool { s := c.Snapshot(); return !s.RejectNew && !s.Critical }

func (c *Controller) AcquireUpload(ctx context.Context, tenant string) (func(), error) {
	c.mu.RLock()
	sem := c.semaphores[tenant]
	c.mu.RUnlock()
	if sem == nil {
		return func() {}, nil
	}
	select {
	case sem <- struct{}{}:
		var once sync.Once
		return func() { once.Do(func() { <-sem }) }, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

func (c *Controller) WaitN(ctx context.Context, tenant string, n int) error {
	if c.Snapshot().Critical {
		return ErrCriticalCapacity
	}
	if n > c.limiter.Burst() {
		n = c.limiter.Burst()
	}
	if err := c.limiter.WaitN(ctx, n); err != nil {
		return err
	}
	c.mu.RLock()
	tl := c.tenants[tenant]
	c.mu.RUnlock()
	if tl != nil {
		if n > tl.Burst() {
			n = tl.Burst()
		}
		if err := tl.WaitN(ctx, n); err != nil {
			return err
		}
	}
	c.uploaded.Add(uint64(n))
	return nil
}

func (c *Controller) ObserveDownload(n int) {
	if n > 0 {
		c.downloaded.Add(uint64(n))
	}
}
func (c *Controller) ObserveDelete(n int64) {
	if n > 0 {
		c.deleted.Add(uint64(n))
	}
}
