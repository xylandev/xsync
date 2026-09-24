package netguard

import (
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestListenerEnforcesPerIPLimit(t *testing.T) {
	inner, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ln := NewListener(inner, Limits{MaxConns: 10, MaxConnsPerIP: 1})
	defer ln.Close()
	accepted := make(chan net.Conn, 4)
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			accepted <- c
		}
	}()
	c1, _ := net.Dial("tcp", ln.Addr().String())
	defer c1.Close()
	first := <-accepted
	c2, _ := net.Dial("tcp", ln.Addr().String())
	defer c2.Close()
	_ = c2.SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, err := c2.Read(make([]byte, 1)); err == nil {
		t.Fatal("second connection from the same address was not closed")
	}
	if ln.Rejected.Load() != 1 {
		t.Fatalf("rejected = %d", ln.Rejected.Load())
	}
	first.Close()
	c3, _ := net.Dial("tcp", ln.Addr().String())
	defer c3.Close()
	select {
	case c := <-accepted:
		c.Close()
	case <-time.After(2 * time.Second):
		t.Fatal("slot not released after close")
	}
}

func TestIdleTimeoutClosesSilentPeer(t *testing.T) {
	inner, _ := net.Listen("tcp", "127.0.0.1:0")
	ln := NewListener(inner, Limits{IdleTimeout: 100 * time.Millisecond})
	defer ln.Close()
	errs := make(chan error, 1)
	go func() {
		c, err := ln.Accept()
		if err != nil {
			errs <- err
			return
		}
		_, err = c.Read(make([]byte, 1))
		errs <- err
	}()
	c, _ := net.Dial("tcp", ln.Addr().String())
	defer c.Close()
	select {
	case err := <-errs:
		if ne, ok := err.(net.Error); !ok || !ne.Timeout() {
			t.Fatalf("err = %v, want timeout", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("idle connection not timed out")
	}
}

func TestAuthLimiterWindow(t *testing.T) {
	a := NewAuthLimiter(2)
	now := time.Now()
	a.now = func() time.Time { return now }
	a.Fail("1.2.3.4")
	a.Fail("1.2.3.4")
	if a.Allow("1.2.3.4") {
		t.Fatal("budget not enforced")
	}
	if !a.Allow("5.6.7.8") {
		t.Fatal("other addresses affected")
	}
	now = now.Add(2 * time.Minute)
	if !a.Allow("1.2.3.4") {
		t.Fatal("window did not slide")
	}
	var nilLimiter *AuthLimiter
	if !nilLimiter.Allow("x") {
		t.Fatal("nil limiter must allow")
	}
	nilLimiter.Fail("x")
}

func TestStallGuardAbortsStalledBody(t *testing.T) {
	srv := httptest.NewServer(StallGuard(200*time.Millisecond, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		buf := make([]byte, 16)
		for {
			if _, err := r.Body.Read(buf); err != nil {
				w.WriteHeader(http.StatusBadRequest)
				return
			}
		}
	})))
	defer srv.Close()
	conn, err := net.Dial("tcp", strings.TrimPrefix(srv.URL, "http://"))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_, _ = conn.Write([]byte("POST / HTTP/1.1\r\nHost: x\r\nContent-Length: 100\r\n\r\nabc"))
	_ = conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	buf := make([]byte, 512)
	n, rerr := conn.Read(buf)
	if ne, ok := rerr.(net.Error); ok && ne.Timeout() {
		t.Fatal("stalled request was never aborted")
	}
	if n > 0 && !strings.Contains(string(buf[:n]), "400") {
		t.Fatalf("unexpected response %q", buf[:n])
	}
}
