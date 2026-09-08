package controller

import (
	"context"
	"errors"
	"io"
	"moto/config"
	"net"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestHTTP2PhysicalMetricsAcrossSharedRulesAndPingTimeout(t *testing.T) {
	resetProcessMetricsForTest()
	proxy := newHTTP2PingTestProxy(t, 0)
	address := proxy.listener.Addr().String()
	firstRules := connectProxyMetricTestRules("initiating-rule", address)
	secondRules := connectProxyMetricTestRules("reusing-rule", address)
	processMetrics.registerRules(firstRules)
	processMetrics.registerRules(secondRules)
	t.Cleanup(func() { processMetrics.unregisterRules(secondRules) })
	manager, target := proxy.newManager(t)
	setupCtx, cancelSetup := context.WithCancel(withConnectProxyRuleName(context.Background(), "initiating-rule"))
	defer cancelSetup()
	first, err := manager.dial(setupCtx, target, "service.example:443")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = first.Close() })
	cancelSetup()
	assertHTTP2PingTestEcho(t, first, "after-setup-cancel")
	const concurrent = 8
	tunnels := make([]net.Conn, concurrent+1)
	tunnels[0] = first
	var group sync.WaitGroup
	errorsReady := make(chan error, concurrent)
	for index := range concurrent {
		group.Add(1)
		go func() {
			defer group.Done()
			ctx, cancel := context.WithTimeout(withConnectProxyRuleName(context.Background(), "reusing-rule"), 3*time.Second)
			defer cancel()
			tunnel, dialErr := manager.dial(ctx, target, "service.example:443")
			tunnels[index+1] = tunnel
			errorsReady <- dialErr
		}()
	}
	group.Wait()
	for _, tunnel := range tunnels[1:] {
		if tunnel != nil {
			t.Cleanup(func() { _ = tunnel.Close() })
		}
	}
	for range concurrent {
		if err := <-errorsReady; err != nil {
			t.Fatal(err)
		}
	}
	// A real ACKed idle PING must not increment the failure family.
	if id := receiveHTTP2PingTestEvent(t, proxy.pings, "healthy shared PING"); id != 1 {
		t.Fatalf("healthy PING connection = %d, want 1", id)
	}
	assertHTTP2PingTestEcho(t, first, "after-healthy-ping")
	snapshot := processMetrics.snapshot()
	firstHandshake := connectProxyAttemptMetricKey{rule: "initiating-rule", target: address, protocol: config.ConnectProxyH2, outcome: connectProxyAttemptSuccess}
	if snapshot.connectProxyHandshakes[firstHandshake] != 1 || len(snapshot.connectProxyHandshakes) != 1 {
		t.Fatalf("physical handshake attribution = %#v, want only initiating rule once", snapshot.connectProxyHandshakes)
	}
	if proxy.accepted.Load() != 1 || snapshot.connectProxyH2PingFailures[address] != 0 {
		t.Fatalf("shared physical connections = %d, PING failures = %d", proxy.accepted.Load(), snapshot.connectProxyH2PingFailures[address])
	}
	// The peer continues keeping TCP/TLS open but withholds the health ACK.
	proxy.dropFirstPingACK.Store(true)
	readErrors := make(chan error, len(tunnels))
	for _, tunnel := range tunnels {
		go func() {
			_, err := tunnel.Read(make([]byte, 1))
			readErrors <- err
		}()
	}
	if id := receiveHTTP2PingTestEvent(t, proxy.droppedPings, "withheld shared PING ACK"); id != 1 {
		t.Fatalf("withheld PING connection = %d, want 1", id)
	}
	for range tunnels {
		select {
		case err := <-readErrors:
			if err == nil || !strings.Contains(err.Error(), "client connection lost") {
				t.Fatalf("lost-PING stream error = %v", err)
			}
		case <-time.After(5 * time.Second):
			t.Fatal("health PING timeout did not release all shared streams")
		}
	}
	if got := processMetrics.snapshot().connectProxyH2PingFailures[address]; got != 1 {
		t.Fatalf("PING failures across %d affected streams = %d, want one physical failure", len(tunnels), got)
	}
	processMetrics.unregisterRules(firstRules)
	recoveryCtx, cancelRecovery := context.WithTimeout(withConnectProxyRuleName(context.Background(), "reusing-rule"), 3*time.Second)
	defer cancelRecovery()
	recovered, err := manager.dial(recoveryCtx, target, "service.example:443")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = recovered.Close() })
	assertHTTP2PingTestEcho(t, recovered, "recovered")
	snapshot = processMetrics.snapshot()
	secondHandshake := connectProxyAttemptMetricKey{rule: "reusing-rule", target: address, protocol: config.ConnectProxyH2, outcome: connectProxyAttemptSuccess}
	if snapshot.connectProxyHandshakes[secondHandshake] != 1 || len(snapshot.connectProxyHandshakes) != 1 || proxy.accepted.Load() != 2 {
		t.Fatalf("recovery handshakes = %#v; physical connections = %d", snapshot.connectProxyHandshakes, proxy.accepted.Load())
	}
	if snapshot.connectProxyH2PingFailures[address] != 1 {
		t.Fatal("retiring the initiating rule reset the shared target PING counter")
	}
}

func TestHTTP2PhysicalHandshakeFailureOutcomes(t *testing.T) {
	t.Run("certificate verification", func(t *testing.T) {
		resetProcessMetricsForTest()
		proxy := newHTTP2ConnectTestServer(t, func(http.ResponseWriter, *http.Request) {})
		target := http2ConnectTestTarget(proxy, "", "")
		rules := connectProxyMetricTestRules("certificate-rule", target.Address)
		processMetrics.registerRules(rules)
		defer processMetrics.unregisterRules(rules)
		manager := newHTTP2ConnectManager(nil) // Deliberately no test CA.
		defer manager.closeIdle()
		ctx, cancel := context.WithTimeout(withConnectProxyRuleName(context.Background(), "certificate-rule"), 3*time.Second)
		defer cancel()
		connection, err := manager.dial(ctx, target, "destination.example:443")
		if connection != nil || err == nil {
			t.Fatalf("untrusted TLS dial = %v, %v", connection, err)
		}
		key := connectProxyAttemptMetricKey{rule: "certificate-rule", target: target.Address, protocol: config.ConnectProxyH2, outcome: connectProxyAttemptTransportError}
		if snapshot := processMetrics.snapshot(); len(snapshot.connectProxyHandshakes) != 1 || snapshot.connectProxyHandshakes[key] != 1 {
			t.Fatalf("failed physical TLS metrics = %#v", snapshot.connectProxyHandshakes)
		}
	})
	for _, canceled := range []bool{false, true} {
		name := "deadline"
		if canceled {
			name = "canceled"
		}
		t.Run(name, func(t *testing.T) {
			resetProcessMetricsForTest()
			listener, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			defer listener.Close()
			accepted := make(chan net.Conn, 1)
			acceptDone := make(chan struct{})
			go func() {
				defer close(acceptDone)
				connection, err := listener.Accept()
				if err == nil {
					accepted <- connection
				}
			}()
			defer func() { _ = listener.Close(); <-acceptDone }()
			address := listener.Addr().String()
			rules := connectProxyMetricTestRules("stalled-rule", address)
			processMetrics.registerRules(rules)
			defer processMetrics.unregisterRules(rules)
			transport := newHTTP2ConnectTransport(http2ConnectTransportKey{address: address, serverName: "127.0.0.1"})
			ctx, cancel := context.WithTimeout(withConnectProxyRuleName(context.Background(), "stalled-rule"), 500*time.Millisecond)
			defer cancel()
			finished := make(chan error, 1)
			go func() {
				connection, err := transport.DialTLSContext(ctx, "tcp", address, transport.TLSClientConfig)
				if connection != nil {
					_ = connection.Close()
				}
				finished <- err
			}()
			select {
			case connection := <-accepted:
				defer connection.Close()
			case <-time.After(2 * time.Second):
				t.Fatal("TLS peer did not accept physical connection")
			}
			outcome, expected := connectProxyAttemptTimeout, context.DeadlineExceeded
			if canceled {
				cancel()
				outcome, expected = connectProxyAttemptCanceled, context.Canceled
			}
			select {
			case err := <-finished:
				if !errors.Is(err, expected) {
					t.Fatalf("physical handshake error = %v, want %v", err, expected)
				}
			case <-time.After(2 * time.Second):
				t.Fatal("physical TLS handshake did not honor context")
			}
			key := connectProxyAttemptMetricKey{rule: "stalled-rule", target: address, protocol: config.ConnectProxyH2, outcome: outcome}
			if snapshot := processMetrics.snapshot(); snapshot.connectProxyHandshakes[key] != 1 || len(snapshot.connectProxyHandshakes) != 1 {
				t.Fatalf("physical %s handshakes = %#v", name, snapshot.connectProxyHandshakes)
			}
		})
	}
}

func TestHTTP2CanceledSetupExcludedFromHistogram(t *testing.T) {
	resetProcessMetricsForTest()
	requestStarted := make(chan struct{}, 1)
	proxy := newHTTP2ConnectTestServer(t, func(_ http.ResponseWriter, request *http.Request) {
		requestStarted <- struct{}{}
		_, _ = io.Copy(io.Discard, request.Body)
	})
	target := http2ConnectTestTarget(proxy, "", "")
	rules := connectProxyMetricTestRules("cancel-rule", target.Address)
	processMetrics.registerRules(rules)
	defer processMetrics.unregisterRules(rules)
	manager := newConnectProxyManager()
	defer manager.close()
	h2 := newHTTP2ConnectTestManager(proxy)
	defer h2.closeIdle()
	manager.dialers[config.ConnectProxyH2] = h2.dial
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	finished := make(chan error, 1)
	go func() {
		connection, err := manager.dialForRule(ctx, "cancel-rule", target, "destination.example:443")
		if connection != nil {
			_ = connection.Close()
		}
		finished <- err
	}()
	select {
	case <-requestStarted:
		cancel()
	case <-time.After(3 * time.Second):
		t.Fatal("proxy did not receive setup")
	}
	select {
	case err := <-finished:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("setup error = %v, want context canceled", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("setup did not honor cancellation")
	}
	snapshot := processMetrics.snapshot()
	key := connectProxyMetricKey{rule: "cancel-rule", target: target.Address, protocol: config.ConnectProxyH2}
	if len(snapshot.connectProxySetupLatency) != 0 || snapshot.connectProxySetupCount[key] != 1 {
		t.Fatal("canceled setup contaminated histogram or disappeared from legacy summary")
	}
	handshake := connectProxyAttemptMetricKey{rule: key.rule, target: key.target, protocol: key.protocol, outcome: connectProxyAttemptSuccess}
	if snapshot.connectProxyHandshakes[handshake] != 1 {
		t.Fatal("canceling CONNECT setup changed its already successful physical TLS handshake")
	}
}

func TestHTTP2HandshakeRecorderRejectsRetiredGeneration(t *testing.T) {
	resetProcessMetricsForTest()
	rules := connectProxyMetricTestRules("reload-rule", "reload.example:443")
	processMetrics.registerRules(rules)
	oldRecorder := metricConnectProxyHandshakeRecorder("reload-rule", "reload.example:443", config.ConnectProxyH2)
	processMetrics.unregisterRules(rules)
	processMetrics.registerRules(rules)
	defer processMetrics.unregisterRules(rules)
	oldRecorder(connectProxyAttemptSuccess)
	if got := len(processMetrics.snapshot().connectProxyHandshakes); got != 0 {
		t.Fatal("old handshake recorder wrote into replacement generation")
	}
	metricConnectProxyHandshakeRecorder("reload-rule", "reload.example:443", config.ConnectProxyH2)(connectProxyAttemptSuccess)
	if got := len(processMetrics.snapshot().connectProxyHandshakes); got != 1 {
		t.Fatal("new handshake recorder failed to observe its own generation")
	}
}
