// Package netguard bounds what an unauthenticated or misbehaving peer can cost
// the server: connection counts, idle and stalled connections, repeated
// authentication failures and oversized request bodies.
package netguard

import (
	"errors"
	"io"
	"net"
	"net/http"
	"sync"
	"sync/atomic"
	"time"
)

// Limits configures a guarded listener.
type Limits struct {
	MaxConns      int
	MaxConnsPerIP int
	// IdleTimeout closes a connection that neither reads nor writes for this
	// long. Zero leaves deadlines to the protocol implementation.
	IdleTimeout time.Duration
}

// Listener enforces connection limits and, optionally, idle deadlines.
type Listener struct {
	net.Listener
	limits Limits
	total  atomic.Int64
	mu     sync.Mutex
	perIP  map[string]int
	wg     sync.WaitGroup
	// Rejected counts connections refused because a limit was reached.
	Rejected atomic.Uint64
}

func NewListener(inner net.Listener, limits Limits) *Listener {
	return &Listener{Listener: inner, limits: limits, perIP: map[string]int{}}
}

// Active returns the number of open connections.
func (l *Listener) Active() int64 { return l.total.Load() }

// Wait blocks until every accepted connection has been closed.
func (l *Listener) Wait() { l.wg.Wait() }

func (l *Listener) Accept() (net.Conn, error) {
	for {
		c, err := l.Listener.Accept()
		if err != nil {
			return nil, err
		}
		ip := hostOf(c.RemoteAddr())
		if !l.admit(ip) {
			l.Rejected.Add(1)
			_ = c.Close()
			continue
		}
		l.wg.Add(1)
		gc := &Conn{Conn: c, idle: l.limits.IdleTimeout}
		gc.onClose = func() { l.leave(ip) }
		return gc, nil
	}
}

func (l *Listener) admit(ip string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.limits.MaxConns > 0 && l.total.Load() >= int64(l.limits.MaxConns) {
		return false
	}
	if l.limits.MaxConnsPerIP > 0 && l.perIP[ip] >= l.limits.MaxConnsPerIP {
		return false
	}
	l.perIP[ip]++
	l.total.Add(1)
	return true
}

func (l *Listener) leave(ip string) {
	l.mu.Lock()
	if l.perIP[ip]--; l.perIP[ip] <= 0 {
		delete(l.perIP, ip)
	}
	l.total.Add(-1)
	l.mu.Unlock()
	l.wg.Done()
}

// Conn is a guarded connection. When an idle timeout is configured, every read
// and write pushes its deadline forward, so only a peer that stops making
// progress is disconnected.
type Conn struct {
	net.Conn
	idle    time.Duration
	once    sync.Once
	onClose func()
}

func (c *Conn) Read(p []byte) (int, error) {
	if c.idle > 0 {
		_ = c.Conn.SetReadDeadline(time.Now().Add(c.idle))
	}
	return c.Conn.Read(p)
}

func (c *Conn) Write(p []byte) (int, error) {
	if c.idle > 0 {
		_ = c.Conn.SetWriteDeadline(time.Now().Add(c.idle))
	}
	return c.Conn.Write(p)
}

func (c *Conn) Close() error {
	err := c.Conn.Close()
	c.once.Do(func() {
		if c.onClose != nil {
			c.onClose()
		}
	})
	return err
}

func hostOf(a net.Addr) string {
	if a == nil {
		return ""
	}
	host, _, err := net.SplitHostPort(a.String())
	if err != nil {
		return a.String()
	}
	return host
}

// HostOf returns the IP part of a network address.
func HostOf(a net.Addr) string { return hostOf(a) }

// AuthLimiter throttles authentication attempts per source address. After
// Budget failures inside Window, further attempts from that address are
// refused until the window slides past them.
type AuthLimiter struct {
	Budget int
	Window time.Duration
	now    func() time.Time
	mu     sync.Mutex
	fails  map[string][]time.Time
	// Blocked counts attempts refused by the limiter.
	Blocked atomic.Uint64
	// Failures counts failed authentications.
	Failures atomic.Uint64
}

func NewAuthLimiter(perMinute int) *AuthLimiter {
	return &AuthLimiter{Budget: perMinute, Window: time.Minute, now: time.Now, fails: map[string][]time.Time{}}
}

func (a *AuthLimiter) prune(ip string, now time.Time) []time.Time {
	list := a.fails[ip]
	keep := list[:0]
	for _, t := range list {
		if now.Sub(t) < a.Window {
			keep = append(keep, t)
		}
	}
	if len(keep) == 0 {
		delete(a.fails, ip)
		return nil
	}
	a.fails[ip] = keep
	return keep
}

// Allow reports whether ip may attempt to authenticate now.
func (a *AuthLimiter) Allow(ip string) bool {
	if a == nil || a.Budget <= 0 {
		return true
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if len(a.prune(ip, a.now())) >= a.Budget {
		a.Blocked.Add(1)
		return false
	}
	return true
}

// Fail records a failed attempt from ip.
func (a *AuthLimiter) Fail(ip string) {
	if a == nil {
		return
	}
	a.Failures.Add(1)
	if a.Budget <= 0 {
		return
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	now := a.now()
	a.fails[ip] = append(a.prune(ip, now), now)
	// Keep the table bounded even under a spray of spoofed sources.
	if len(a.fails) > 100000 {
		for k := range a.fails {
			a.prune(k, now)
		}
	}
}

// ErrThrottled is returned when an address has exhausted its failure budget.
var ErrThrottled = errors.New("too many failed authentication attempts; try again later")

// StallGuard wraps an HTTP handler so that a request whose body or response
// makes no progress for idle is aborted, without capping the total duration
// of a large transfer the way http.Server.ReadTimeout would.
//
// Deadlines are armed only around actual reads and writes, never up front: a
// handler that works for a while before answering (a multipart completion, a
// long poll) must not find its write deadline already spent. Once the body has
// been read to the end the read deadline is cleared, so the server's
// background read cannot time out and cancel the request while the handler is
// still working.
func StallGuard(idle time.Duration, next http.Handler) http.Handler {
	if idle <= 0 {
		return next
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rc := http.NewResponseController(w)
		if r.Body != nil && r.Body != http.NoBody {
			r.Body = &deadlineBody{ReadCloser: r.Body, rc: rc, idle: idle}
		}
		next.ServeHTTP(&deadlineWriter{ResponseWriter: w, rc: rc, idle: idle}, r)
	})
}

type deadlineBody struct {
	io.ReadCloser
	rc   *http.ResponseController
	idle time.Duration
}

func (b *deadlineBody) Read(p []byte) (int, error) {
	_ = b.rc.SetReadDeadline(time.Now().Add(b.idle))
	n, err := b.ReadCloser.Read(p)
	if err == io.EOF {
		_ = b.rc.SetReadDeadline(time.Time{})
	}
	return n, err
}

type deadlineWriter struct {
	http.ResponseWriter
	rc   *http.ResponseController
	idle time.Duration
}

func (w *deadlineWriter) Write(p []byte) (int, error) {
	_ = w.rc.SetWriteDeadline(time.Now().Add(w.idle))
	return w.ResponseWriter.Write(p)
}

func (w *deadlineWriter) ReadFrom(r io.Reader) (int64, error) {
	// Copy in chunks so the write deadline keeps moving during a long
	// response instead of expiring halfway through a healthy download.
	buf := make([]byte, 256<<10)
	var total int64
	for {
		n, rerr := r.Read(buf)
		if n > 0 {
			wn, werr := w.Write(buf[:n])
			total += int64(wn)
			if werr != nil {
				return total, werr
			}
		}
		if rerr == io.EOF {
			return total, nil
		}
		if rerr != nil {
			return total, rerr
		}
	}
}

func (w *deadlineWriter) Flush() {
	if f, ok := w.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

func (w *deadlineWriter) Unwrap() http.ResponseWriter { return w.ResponseWriter }
