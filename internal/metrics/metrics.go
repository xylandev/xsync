// Package metrics is a small Prometheus text-format registry: labelled
// counters, histograms and gauges computed at scrape time. It avoids pulling
// a client library into a binary that exports a few dozen series.
package metrics

import (
	"fmt"
	"io"
	"math"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
)

type Registry struct {
	mu       sync.Mutex
	families []family
}

type family interface {
	name() string
	write(w io.Writer)
}

func New() *Registry { return &Registry{} }

func (r *Registry) add(f family) {
	r.mu.Lock()
	r.families = append(r.families, f)
	r.mu.Unlock()
}

// Write renders every family in the Prometheus text exposition format.
func (r *Registry) Write(w io.Writer) {
	r.mu.Lock()
	fams := append([]family(nil), r.families...)
	r.mu.Unlock()
	sort.SliceStable(fams, func(i, j int) bool { return fams[i].name() < fams[j].name() })
	for _, f := range fams {
		f.write(w)
	}
}

func header(w io.Writer, name, help, typ string) {
	fmt.Fprintf(w, "# HELP %s %s\n# TYPE %s %s\n", name, strings.ReplaceAll(help, "\n", " "), name, typ)
}

func escape(v string) string {
	v = strings.ReplaceAll(v, `\`, `\\`)
	v = strings.ReplaceAll(v, "\n", `\n`)
	return strings.ReplaceAll(v, `"`, `\"`)
}

func labelString(names, values []string, extra ...string) string {
	if len(names) == 0 && len(extra) == 0 {
		return ""
	}
	parts := make([]string, 0, len(names)+len(extra)/2)
	for i, n := range names {
		v := ""
		if i < len(values) {
			v = values[i]
		}
		parts = append(parts, n+`="`+escape(v)+`"`)
	}
	for i := 0; i+1 < len(extra); i += 2 {
		parts = append(parts, extra[i]+`="`+escape(extra[i+1])+`"`)
	}
	return "{" + strings.Join(parts, ",") + "}"
}

func formatFloat(v float64) string {
	switch {
	case math.IsInf(v, 1):
		return "+Inf"
	case math.IsInf(v, -1):
		return "-Inf"
	case math.IsNaN(v):
		return "NaN"
	}
	return strconv.FormatFloat(v, 'g', -1, 64)
}

// Counter is a monotonically increasing value.
type Counter struct{ bits atomic.Uint64 }

func (c *Counter) Add(v float64) {
	for {
		old := c.bits.Load()
		if c.bits.CompareAndSwap(old, math.Float64bits(math.Float64frombits(old)+v)) {
			return
		}
	}
}
func (c *Counter) Inc()           { c.Add(1) }
func (c *Counter) Value() float64 { return math.Float64frombits(c.bits.Load()) }

type CounterVec struct {
	n, help string
	labels  []string
	mu      sync.Mutex
	series  map[string]*Counter
	values  map[string][]string
}

func (r *Registry) CounterVec(name, help string, labels ...string) *CounterVec {
	v := &CounterVec{n: name, help: help, labels: labels, series: map[string]*Counter{}, values: map[string][]string{}}
	r.add(v)
	return v
}

func (v *CounterVec) With(values ...string) *Counter {
	key := strings.Join(values, "\x00")
	v.mu.Lock()
	defer v.mu.Unlock()
	c := v.series[key]
	if c == nil {
		c = &Counter{}
		v.series[key] = c
		v.values[key] = append([]string(nil), values...)
	}
	return c
}

func (v *CounterVec) name() string { return v.n }
func (v *CounterVec) write(w io.Writer) {
	header(w, v.n, v.help, "counter")
	v.mu.Lock()
	keys := make([]string, 0, len(v.series))
	for k := range v.series {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		fmt.Fprintf(w, "%s%s %s\n", v.n, labelString(v.labels, v.values[k]), formatFloat(v.series[k].Value()))
	}
	v.mu.Unlock()
}

// Histogram records observations into cumulative buckets.
type Histogram struct {
	bounds []float64
	counts []atomic.Uint64
	sum    Counter
	count  atomic.Uint64
}

func (h *Histogram) Observe(v float64) {
	for i, b := range h.bounds {
		if v <= b {
			h.counts[i].Add(1)
		}
	}
	h.sum.Add(v)
	h.count.Add(1)
}

type HistogramVec struct {
	n, help string
	labels  []string
	bounds  []float64
	mu      sync.Mutex
	series  map[string]*Histogram
	values  map[string][]string
}

// DefaultLatencyBuckets suit request latencies in seconds.
var DefaultLatencyBuckets = []float64{0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10, 30, 60}

func (r *Registry) HistogramVec(name, help string, bounds []float64, labels ...string) *HistogramVec {
	v := &HistogramVec{n: name, help: help, labels: labels, bounds: bounds, series: map[string]*Histogram{}, values: map[string][]string{}}
	r.add(v)
	return v
}

func (v *HistogramVec) With(values ...string) *Histogram {
	key := strings.Join(values, "\x00")
	v.mu.Lock()
	defer v.mu.Unlock()
	h := v.series[key]
	if h == nil {
		h = &Histogram{bounds: v.bounds, counts: make([]atomic.Uint64, len(v.bounds))}
		v.series[key] = h
		v.values[key] = append([]string(nil), values...)
	}
	return h
}

func (v *HistogramVec) name() string { return v.n }
func (v *HistogramVec) write(w io.Writer) {
	header(w, v.n, v.help, "histogram")
	v.mu.Lock()
	keys := make([]string, 0, len(v.series))
	for k := range v.series {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		h, vals := v.series[k], v.values[k]
		for i, b := range h.bounds {
			fmt.Fprintf(w, "%s_bucket%s %d\n", v.n, labelString(v.labels, vals, "le", formatFloat(b)), h.counts[i].Load())
		}
		fmt.Fprintf(w, "%s_bucket%s %d\n", v.n, labelString(v.labels, vals, "le", "+Inf"), h.count.Load())
		fmt.Fprintf(w, "%s_sum%s %s\n", v.n, labelString(v.labels, vals), formatFloat(h.sum.Value()))
		fmt.Fprintf(w, "%s_count%s %d\n", v.n, labelString(v.labels, vals), h.count.Load())
	}
	v.mu.Unlock()
}

// GaugeFunc computes a gauge family at scrape time. The collector calls emit
// once per series.
type gaugeFunc struct {
	n, help, typ string
	labels       []string
	collect      func(emit func(value float64, labelValues ...string))
}

func (r *Registry) GaugeFunc(name, help string, labels []string, collect func(emit func(value float64, labelValues ...string))) {
	r.add(&gaugeFunc{n: name, help: help, typ: "gauge", labels: labels, collect: collect})
}

// CounterFunc is GaugeFunc for values that only increase.
func (r *Registry) CounterFunc(name, help string, labels []string, collect func(emit func(value float64, labelValues ...string))) {
	r.add(&gaugeFunc{n: name, help: help, typ: "counter", labels: labels, collect: collect})
}

func (g *gaugeFunc) name() string { return g.n }
func (g *gaugeFunc) write(w io.Writer) {
	header(w, g.n, g.help, g.typ)
	g.collect(func(value float64, labelValues ...string) {
		fmt.Fprintf(w, "%s%s %s\n", g.n, labelString(g.labels, labelValues), formatFloat(value))
	})
}
