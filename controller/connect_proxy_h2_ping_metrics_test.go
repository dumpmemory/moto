package controller

import (
	"crypto/tls"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"testing"
)

func TestHTTP2PingMetricObserverCountsPerPhysicalConnection(t *testing.T) {
	var failures, unrelated atomic.Int64
	counter := func(kind string) {
		if kind == "conn_close_lost_ping" {
			failures.Add(1)
		} else {
			unrelated.Add(1)
		}
	}
	first, peer := net.Pipe()
	defer peer.Close()
	observed, callback := wrapHTTP2PingMetricConnection(first, counter)
	defer observed.Close()
	var group sync.WaitGroup
	for range 64 {
		group.Add(1)
		go func() { defer group.Done(); callback("conn_close_lost_ping") }()
	}
	group.Wait()
	if got := failures.Load(); got != 1 {
		t.Fatalf("concurrent failure count = %d, want 1", got)
	}
	_ = observed.Close()
	second, peer2 := net.Pipe()
	defer peer2.Close()
	next, nextCallback := wrapHTTP2PingMetricConnection(second, counter)
	defer next.Close()
	callback("conn_close_lost_ping")
	nextCallback("conn_close_lost_ping")
	nextCallback("conn_close_lost_ping")
	if got := failures.Load(); got != 2 {
		t.Fatalf("successive physical failures = %d, want 2", got)
	}
	callback("read_frame_eof")
	callback("read_frame_eof")
	if unrelated.Load() != 2 {
		t.Fatal("unrelated CountError notifications were suppressed")
	}
}

func TestHTTP2PingMetricObserverIgnoresTerminatedConnections(t *testing.T) {
	for _, readEOF := range []bool{false, true} {
		var count atomic.Int64
		first, peer := net.Pipe()
		observed, callback := wrapHTTP2PingMetricConnection(first, func(string) { count.Add(1) })
		if readEOF {
			_ = peer.Close()
			if _, err := observed.Read(make([]byte, 1)); err != io.EOF {
				t.Fatalf("read = %v, want EOF", err)
			}
		} else {
			_ = observed.Close()
		}
		callback("conn_close_lost_ping")
		if count.Load() != 0 {
			t.Fatal("terminated connection created a PING failure")
		}
		_ = observed.Close()
		_ = peer.Close()
	}
}

func TestHTTP2PingMetricObserverCloseRace(t *testing.T) {
	for range 32 {
		var count atomic.Int64
		first, peer := net.Pipe()
		observed, callback := wrapHTTP2PingMetricConnection(first, func(string) { count.Add(1) })
		var group sync.WaitGroup
		for index := range 16 {
			group.Add(1)
			go func() {
				defer group.Done()
				if index%2 == 0 {
					_ = observed.Close()
				} else {
					callback("conn_close_lost_ping")
				}
			}()
		}
		group.Wait()
		before := count.Load()
		callback("conn_close_lost_ping")
		if before > 1 || count.Load() != before {
			t.Fatal("close race duplicated or revived physical PING failure")
		}
		_ = peer.Close()
	}
}

type http2PingMetricTLSFixture struct{ net.Conn }

func (*http2PingMetricTLSFixture) ConnectionState() tls.ConnectionState {
	return tls.ConnectionState{Version: tls.VersionTLS13, NegotiatedProtocol: "h2"}
}

func TestHTTP2PingMetricObserverPreservesOptionalTLSState(t *testing.T) {
	first, peer := net.Pipe()
	defer peer.Close()
	plain, _ := wrapHTTP2PingMetricConnection(first, nil)
	defer plain.Close()
	if _, ok := plain.(interface{ ConnectionState() tls.ConnectionState }); ok {
		t.Fatal("invented TLS state for non-TLS adapter")
	}
	wrapped, callback := wrapHTTP2PingMetricConnection(&http2PingMetricTLSFixture{Conn: first}, nil)
	state, ok := wrapped.(interface{ ConnectionState() tls.ConnectionState })
	if !ok || state.ConnectionState().NegotiatedProtocol != "h2" {
		t.Fatal("TLS state lost")
	}
	callback("conn_close_lost_ping") // A missing metrics sink is safe.
}

func TestHTTP2PingMetricObserverKeepsRetiredTargetIsolated(t *testing.T) {
	resetProcessMetricsForTest()
	const address = "reload.example:443"
	rules := connectProxyMetricTestRules("reload-ping-rule", address)
	processMetrics.registerRules(rules)
	first, peer := net.Pipe()
	defer peer.Close()
	old, oldCallback := wrapHTTP2PingMetricConnection(first, metricConnectProxyH2ErrorCounter(address))
	defer old.Close()
	processMetrics.unregisterRules(rules)
	processMetrics.registerRules(rules)
	defer processMetrics.unregisterRules(rules)
	oldCallback("conn_close_lost_ping")
	if got := processMetrics.snapshot().connectProxyH2PingFailures[address]; got != 0 {
		t.Fatalf("old connection wrote %d failures into reloaded target", got)
	}
	second, peer2 := net.Pipe()
	defer peer2.Close()
	current, currentCallback := wrapHTTP2PingMetricConnection(second, metricConnectProxyH2ErrorCounter(address))
	defer current.Close()
	currentCallback("conn_close_lost_ping")
	if got := processMetrics.snapshot().connectProxyH2PingFailures[address]; got != 1 {
		t.Fatalf("current connection failures = %d, want 1", got)
	}
}
