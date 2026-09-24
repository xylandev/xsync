package metrics

import (
	"math"
	"strings"
	"testing"
)

func TestExposition(t *testing.T) {
	r := New()
	c := r.CounterVec("req_total", "Requests.", "route")
	c.With(`a"b`).Add(2)
	h := r.HistogramVec("lat_seconds", "Latency.", []float64{0.1, 1}, "route")
	h.With("x").Observe(0.5)
	r.GaugeFunc("limit", "Limit.", nil, func(emit func(float64, ...string)) { emit(math.Inf(1)) })
	var b strings.Builder
	r.Write(&b)
	out := b.String()
	for _, want := range []string{
		"# TYPE req_total counter", `req_total{route="a\"b"} 2`,
		`lat_seconds_bucket{route="x",le="0.1"} 0`, `lat_seconds_bucket{route="x",le="1"} 1`,
		`lat_seconds_bucket{route="x",le="+Inf"} 1`, `lat_seconds_count{route="x"} 1`,
		"limit +Inf",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in:\n%s", want, out)
		}
	}
}
