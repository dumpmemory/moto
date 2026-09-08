package controller

import (
	"context"
	"fmt"
	"moto/config"
	"net"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

func connectProxyMetricTestRules(rule, target string) []*config.Rule {
	return []*config.Rule{{Name: rule, Targets: []*config.Target{{
		Address: target, ConnectProxy: &config.ConnectProxyConfig{Protocols: []string{config.ConnectProxyH2, config.ConnectProxyH3}},
	}}}}
}

func TestConnectProxySetupHistogramBoundariesAndCancellation(t *testing.T) {
	resetProcessMetricsForTest()
	rules := connectProxyMetricTestRules("setup-rule", "proxy.example:443")
	processMetrics.registerRules(rules)
	defer processMetrics.unregisterRules(rules)
	key := connectProxyMetricKey{rule: "setup-rule", target: "proxy.example:443", protocol: config.ConnectProxyH2}
	observations := []time.Duration{
		-time.Second, 0, 5 * time.Millisecond, 5*time.Millisecond + time.Nanosecond,
		10 * time.Millisecond, 25 * time.Millisecond, 250 * time.Millisecond,
		500 * time.Millisecond, time.Second, 3 * time.Second, 10 * time.Second, 11 * time.Second,
	}
	var expectedNanos uint64
	for _, duration := range observations {
		metricConnectProxyAttempt(key.rule, key.target, key.protocol, connectProxyAttemptSuccess, duration, true)
		if duration > 0 {
			expectedNanos += uint64(duration)
		}
	}
	metricConnectProxyAttempt(key.rule, key.target, key.protocol, connectProxyAttemptTimeout, 2*time.Second, true)
	expectedNanos += uint64(2 * time.Second)
	metricConnectProxyAttempt(key.rule, key.target, key.protocol, connectProxyAttemptCanceled, time.Second, true)
	metricConnectProxyAttempt(key.rule, key.target, key.protocol, connectProxyAttemptCooldown, time.Second, false)
	metricConnectProxyAttempt(key.rule, key.target, key.protocol, connectProxyAttemptUnavailable, time.Second, false)
	metricConnectProxyAttempt(key.rule, key.target, key.protocol, connectProxyAttemptCapacity, time.Second, false)
	metricConnectProxyAttempt(key.rule, key.target, key.protocol, connectProxyAttemptCapacity, time.Second, true)
	snapshot := processMetrics.snapshot()
	histogram := snapshot.connectProxySetupLatency[key]
	if histogram.count != 13 || histogram.nanos != expectedNanos {
		t.Fatalf("histogram = %#v, want 13 observations summing to %dns", histogram, expectedNanos)
	}
	if snapshot.connectProxySetupCount[key] != 15 || snapshot.connectProxySetupNanos[key] != expectedNanos+uint64(2*time.Second) {
		t.Fatal("legacy summary no longer includes the canceled/capacity observed setups")
	}
	if got := snapshot.connectProxyAttempts[connectProxyAttemptMetricKey{rule: key.rule, target: key.target, protocol: key.protocol, outcome: connectProxyAttemptCanceled}]; got != 1 {
		t.Fatalf("canceled attempts = %d, want 1", got)
	}
	body := renderPrometheusMetrics()
	labels := `rule="setup-rule",target="proxy.example:443",protocol="h2"`
	// Literal expected cumulative counts exercise inclusive finite boundaries
	// and the overflow bucket independently from the recording implementation.
	for _, expected := range []struct {
		bound string
		count int
	}{
		{"0.005", 3}, {"0.01", 5}, {"0.025", 6}, {"0.05", 6},
		{"0.1", 6}, {"0.25", 7}, {"0.5", 8}, {"1", 9},
		{"2", 10}, {"3", 11}, {"5", 11}, {"10", 12}, {"+Inf", 13},
	} {
		line := fmt.Sprintf("moto_connect_proxy_setup_latency_seconds_bucket{%s,le=%q} %d\n", labels, expected.bound, expected.count)
		if !strings.Contains(body, line) {
			t.Fatalf("missing histogram bucket %q", line)
		}
	}
	for _, line := range []string{
		"# TYPE moto_connect_proxy_setup_duration_seconds summary\n",
		"# TYPE moto_connect_proxy_setup_latency_seconds histogram\n",
		"moto_connect_proxy_setup_latency_seconds_count{" + labels + "} 13\n",
		"moto_connect_proxy_setup_duration_seconds_count{" + labels + "} 15\n",
		"moto_connect_proxy_setup_latency_seconds_sum{" + labels + "} " + strconv.FormatFloat(float64(expectedNanos)/float64(time.Second), 'g', -1, 64) + "\n",
	} {
		if !strings.Contains(body, line) {
			t.Fatalf("missing metric line %q", line)
		}
	}
	if strings.Count(body, "# TYPE moto_connect_proxy_setup_latency_seconds ") != 1 ||
		strings.Count(body, "# TYPE moto_connect_proxy_setup_duration_seconds ") != 1 {
		t.Fatal("duplicate/conflicting setup metric TYPE declarations")
	}
}

func TestConnectProxyPhysicalMetricsConcurrentBoundedAndRetired(t *testing.T) {
	resetProcessMetricsForTest()
	const target = "shared.example:443"
	firstRules := connectProxyMetricTestRules("first-rule", target)
	secondRules := connectProxyMetricTestRules("second-rule", target)
	processMetrics.registerRules(firstRules)
	processMetrics.registerRules(firstRules) // Overlapping generations.
	processMetrics.registerRules(secondRules)
	countPingError := metricConnectProxyH2ErrorCounter(target)
	const workers, attempts = 8, 100
	var group sync.WaitGroup
	for range workers {
		group.Add(1)
		go func() {
			defer group.Done()
			for range attempts {
				metricConnectProxyAttempt("first-rule", target, config.ConnectProxyH2, connectProxyAttemptSuccess, 10*time.Millisecond, true)
				metricConnectProxyProtocolHandshake("first-rule", target, config.ConnectProxyH2, connectProxyAttemptSuccess)
				countPingError("conn_close_lost_ping")
				_ = processMetrics.snapshot()
			}
		}()
	}
	group.Wait()
	key := connectProxyMetricKey{rule: "first-rule", target: target, protocol: config.ConnectProxyH2}
	snapshot := processMetrics.snapshot()
	if histogram := snapshot.connectProxySetupLatency[key]; histogram.count != workers*attempts || histogram.buckets[1] != workers*attempts {
		t.Fatalf("concurrent histogram = %#v", histogram)
	}
	if snapshot.connectProxyH2PingFailures[target] != workers*attempts {
		t.Fatalf("concurrent PING failures = %#v", snapshot.connectProxyH2PingFailures)
	}
	// Snapshots own value copies, including the complete fixed-size bucket array.
	metricConnectProxyAttempt("first-rule", target, config.ConnectProxyH2, connectProxyAttemptSuccess, 10*time.Millisecond, true)
	if snapshot.connectProxySetupLatency[key].count != workers*attempts {
		t.Fatal("recording changed a previous histogram snapshot")
	}
	for range 100 {
		metricConnectProxyAttempt("unknown-rule", target, config.ConnectProxyH2, connectProxyAttemptSuccess, time.Second, true)
		metricConnectProxyAttempt("first-rule", "destination-controlled:443", config.ConnectProxyH2, connectProxyAttemptSuccess, time.Second, true)
		metricConnectProxyAttempt("first-rule", target, "unknown-protocol", connectProxyAttemptSuccess, time.Second, true)
		metricConnectProxyProtocolHandshake("first-rule", target, config.ConnectProxyH2, "unknown-outcome")
		metricConnectProxyProtocolHandshake("first-rule", target, "unknown-protocol", connectProxyAttemptSuccess)
		metricConnectProxyProtocolHandshake("unknown-rule", target, config.ConnectProxyH2, connectProxyAttemptSuccess)
		metricConnectProxyH2ErrorCounter("destination-controlled:443")("conn_close_lost_ping")
		countPingError("client-controlled-error")
		countPingError("ping_timeout") // Not x/net's event.
	}
	snapshot = processMetrics.snapshot()
	if len(snapshot.connectProxySetupLatency) != 1 || len(snapshot.connectProxyHandshakes) != 1 || len(snapshot.connectProxyH2PingFailures) != 1 || snapshot.connectProxyH2PingFailures[target] != workers*attempts {
		t.Fatal("unregistered or arbitrary labels/events changed bounded physical metrics")
	}
	processMetrics.unregisterRules(firstRules)
	if processMetrics.snapshot().connectProxySetupLatency[key].count != workers*attempts+1 {
		t.Fatal("overlapping generation lost its histogram")
	}
	processMetrics.unregisterRules(firstRules)
	metricConnectProxyAttempt("first-rule", target, config.ConnectProxyH2, connectProxyAttemptSuccess, time.Second, true)
	metricConnectProxyProtocolHandshake("first-rule", target, config.ConnectProxyH2, connectProxyAttemptSuccess)
	countPingError("conn_close_lost_ping")
	snapshot = processMetrics.snapshot()
	if len(snapshot.connectProxySetupLatency) != 0 || len(snapshot.connectProxyHandshakes) != 0 || snapshot.connectProxyH2PingFailures[target] != workers*attempts+1 {
		t.Fatal("retired rule was revived or remaining rule lost shared target metrics")
	}
	body := renderPrometheusMetrics()
	want := `moto_connect_proxy_h2_ping_failures_total{target="shared.example:443",protocol="h2"} 801` + "\n"
	if !strings.Contains(body, want) {
		t.Fatalf("missing target-scoped metric %q", want)
	}
	processMetrics.unregisterRules(secondRules)
	countPingError("conn_close_lost_ping")
	snapshot = processMetrics.snapshot()
	if len(snapshot.connectProxyH2PingFailures) != 0 || len(snapshot.connectProxySetupLatency) != 0 {
		t.Fatal("last target retirement retained or revived physical metrics")
	}
	processMetrics.mu.RLock()
	refs := len(processMetrics.connectProxyH2TargetRefs)
	processMetrics.mu.RUnlock()
	if refs != 0 {
		t.Fatalf("retired physical target refs = %d, want 0", refs)
	}
	processMetrics.registerRules(firstRules)
	defer processMetrics.unregisterRules(firstRules)
	countPingError("conn_close_lost_ping")
	if got := processMetrics.snapshot().connectProxyH2PingFailures[target]; got != 0 {
		t.Fatalf("old transport hook contaminated re-registered target: %d", got)
	}
	metricConnectProxyH2ErrorCounter(target)("conn_close_lost_ping")
	if got := processMetrics.snapshot().connectProxyH2PingFailures[target]; got != 1 {
		t.Fatalf("new transport hook recorded %d PING failures, want 1", got)
	}
}

func TestConnectProxySetupHistogramExcludesActualHTTP3PoolCapacity(t *testing.T) {
	resetProcessMetricsForTest()
	rules := connectProxyMetricTestRules("capacity-rule", "pool.example:443")
	target := rules[0].Targets[0]
	target.ConnectProxy.Protocols = []string{config.ConnectProxyH3, config.ConnectProxyH2}
	processMetrics.registerRules(rules)
	defer processMetrics.unregisterRules(rules)
	manager := newConnectProxyManager()
	defer manager.close()
	manager.h3.streamsPerTransport = 1
	manager.h3.maxTransportsPerKey = 1
	// Reserve the only real pool slot before dispatch. The next H3 dial must
	// fail inside acquireTransport, before starting any physical handshake or
	// writing CONNECT headers; this is not a stubbed capacity error.
	_, _, release, err := manager.h3.acquireTransport(http3ConnectTransportKey{address: target.Address})
	if err != nil {
		t.Fatal(err)
	}
	defer release()
	manager.dialers[config.ConnectProxyH2] = func(context.Context, *config.Target, string) (net.Conn, error) {
		connection, peer := net.Pipe()
		_ = peer.Close()
		return connection, nil
	}
	connection, err := manager.dialForRule(context.Background(), "capacity-rule", target, "destination.example:443")
	if err != nil {
		t.Fatal(err)
	}
	_ = connection.Close()
	snapshot := processMetrics.snapshot()
	h3Key := connectProxyMetricKey{rule: "capacity-rule", target: target.Address, protocol: config.ConnectProxyH3}
	if snapshot.connectProxySetupCount[h3Key] != 1 {
		t.Fatal("legacy summary lost the local pool-capacity dial observation")
	}
	if _, exists := snapshot.connectProxySetupLatency[h3Key]; exists {
		t.Fatal("local H3 pool saturation became a CONNECT latency observation")
	}
	if got := snapshot.connectProxyAttempts[connectProxyAttemptMetricKey{rule: h3Key.rule, target: h3Key.target, protocol: h3Key.protocol, outcome: connectProxyAttemptCapacity}]; got != 1 {
		t.Fatalf("actual local capacity attempts = %d, want 1", got)
	}
	h2Key := connectProxyMetricKey{rule: h3Key.rule, target: h3Key.target, protocol: config.ConnectProxyH2}
	if snapshot.connectProxySetupLatency[h2Key].count != 1 || len(snapshot.connectProxyHandshakes) != 0 {
		t.Fatal("capacity fallback did not keep the H2 setup observation separate from physical handshakes")
	}
}
