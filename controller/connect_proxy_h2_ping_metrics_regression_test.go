package controller

import (
	"net"
	"strings"
	"testing"
	"time"
)

// Wait beyond two fixture read-idle intervals. An old read-loop timer may
// wake after the socket has already closed; no new physical failure occurred.
func assertHTTP2PingFailureCountSettled(t *testing.T, address string, want uint64) {
	t.Helper()
	deadline := time.Now().Add(350 * time.Millisecond)
	for {
		if got := processMetrics.snapshot().connectProxyH2PingFailures[address]; got != want {
			t.Fatalf("settled PING failures = %d, want %d independent physical failures", got, want)
		}
		if time.Now().After(deadline) {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func TestHTTP2ConnectPingMetricsCountSuccessivePhysicalFailures(t *testing.T) {
	resetProcessMetricsForTest()
	proxy := newHTTP2PingTestProxy(t, 0)
	address := proxy.listener.Addr().String()
	rules := connectProxyMetricTestRules("successive-ping-rule", address)
	processMetrics.registerRules(rules)
	defer processMetrics.unregisterRules(rules)
	manager, target := proxy.newManager(t)
	for generation := uint64(1); generation <= 2; generation++ {
		first := dialHTTP2PingTestTunnel(t, manager, target)
		second := dialHTTP2PingTestTunnel(t, manager, target)
		assertHTTP2PingTestEcho(t, first, "before-failure")
		if got := proxy.accepted.Load(); got != generation {
			t.Fatalf("connections = %d, want shared generation %d", got, generation)
		}
		proxy.dropPingACKThrough.Store(generation)
		failed := make(chan error, 2)
		for _, tunnel := range []net.Conn{first, second} {
			go func() { _, err := tunnel.Read(make([]byte, 1)); failed <- err }()
		}
		if got := receiveHTTP2PingTestEvent(t, proxy.droppedPings, "lost health ACK"); got != generation {
			t.Fatalf("lost ACK generation = %d, want %d", got, generation)
		}
		for range 2 {
			select {
			case err := <-failed:
				if err == nil || !strings.Contains(err.Error(), "client connection lost") {
					t.Fatalf("failed tunnel error = %v", err)
				}
			case <-time.After(5 * time.Second):
				t.Fatal("PING loss did not release blocked stream")
			}
		}
		assertHTTP2PingFailureCountSettled(t, address, generation)
	}
	third := dialHTTP2PingTestTunnel(t, manager, target)
	assertHTTP2PingTestEcho(t, third, "healthy-successor")
	assertHTTP2PingFailureCountSettled(t, address, 2)
	if got := proxy.accepted.Load(); got != 3 {
		t.Fatalf("connections after two failures and recovery = %d, want 3", got)
	}
}

func TestHTTP2ConnectPingMetricsIgnoreNotificationsAfterNormalClose(t *testing.T) {
	for _, remoteClose := range []bool{false, true} {
		name := "local_idle_close"
		if remoteClose {
			name = "remote_eof"
		}
		t.Run(name, func(t *testing.T) {
			resetProcessMetricsForTest()
			proxy := newHTTP2PingTestProxy(t, 0)
			address := proxy.listener.Addr().String()
			rules := connectProxyMetricTestRules("normal-close-rule", address)
			processMetrics.registerRules(rules)
			defer processMetrics.unregisterRules(rules)
			manager, target := proxy.newManager(t)
			tunnel := dialHTTP2PingTestTunnel(t, manager, target)
			assertHTTP2PingTestEcho(t, tunnel, "normal-close")
			if remoteClose {
				proxy.mu.Lock()
				for connection := range proxy.connections {
					_ = connection.Close()
				}
				proxy.mu.Unlock()
			} else {
				_ = tunnel.Close()
			}
			deadline := time.After(3 * time.Second)
			for {
				manager.closeIdle()
				select {
				case <-proxy.closed:
					assertHTTP2PingFailureCountSettled(t, address, 0)
					return
				case <-deadline:
					t.Fatal("normal physical connection did not close")
				case <-time.After(10 * time.Millisecond):
				}
			}
		})
	}
}
