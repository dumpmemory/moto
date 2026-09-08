package controller

import (
	"context"
	"strings"
	"testing"
	"time"

	"moto/config"
)

func TestActiveHealthRecoveryGaugesExposeProgressAndPreciseTimestamps(t *testing.T) {
	runtime := newRoutingRuntime()
	defer runtime.stopBackground()
	rule := activeHealthTestRule("active-gauges", "upstream:443", config.HealthCheckTCP)
	key := activeHealthKey{rule: rule, address: rule.Targets[0].Address}
	manager := runtime.health
	now := time.Unix(1_788_000_000, 125_000_000)
	manager.now = func() time.Time { return now }
	manager.observe(key, *rule.HealthCheck, false)
	manager.observe(key, *rule.HealthCheck, false)
	manager.observe(key, *rule.HealthCheck, true)
	manager.mu.Lock()
	manager.states[key].nextProbeAt = now.Add(activeHealthRecoveryConfirmCap)
	manager.mu.Unlock()
	assertSamples := func(wants map[string]string) {
		t.Helper()
		var output strings.Builder
		runtime.renderOperationalGauges(&output)
		body := output.String()
		for metric, value := range wants {
			want := metric + `{rule="active-gauges",mode="normal",target="upstream:443"} ` + value + "\n"
			if !strings.Contains(body, want) {
				t.Errorf("metrics missing %q", want)
			}
			if !strings.Contains(body, "# TYPE "+metric+" gauge\n") {
				t.Errorf("missing gauge declaration for %s", metric)
			}
		}
	}
	assertSamples(map[string]string{
		"moto_active_health_unhealthy":                            "1",
		"moto_active_health_recovery_successes":                   "1",
		"moto_active_health_recovery_required_successes":          "2",
		"moto_active_health_next_probe_timestamp_seconds":         "1788000001.625",
		"moto_active_health_probe_in_flight":                      "0",
		"moto_active_health_last_probe_success_timestamp_seconds": "1788000000.125",
		"moto_active_health_last_recovery_timestamp_seconds":      "0",
	})

	manager.probe = func(context.Context, string, config.HealthCheckConfig, string) error {
		assertSamples(map[string]string{
			"moto_active_health_next_probe_timestamp_seconds": "0",
			"moto_active_health_probe_in_flight":              "1",
			"moto_active_health_recovery_successes":           "1",
		})
		return nil
	}
	now = now.Add(1500 * time.Millisecond)
	job := activeHealthJob{key: key, target: key.address, check: *rule.HealthCheck, failureConclusive: true}
	if !manager.runProbe(context.Background(), job) {
		t.Fatal("recovery probe canceled")
	}
	assertSamples(map[string]string{
		"moto_active_health_unhealthy":                            "0",
		"moto_active_health_recovery_successes":                   "0",
		"moto_active_health_recovery_required_successes":          "2",
		"moto_active_health_next_probe_timestamp_seconds":         "0",
		"moto_active_health_probe_in_flight":                      "0",
		"moto_active_health_last_probe_success_timestamp_seconds": "1788000001.625",
		"moto_active_health_last_recovery_timestamp_seconds":      "1788000001.625",
	})
	// A healthy success updates the last successful probe, not recovery history.
	now = now.Add(10 * time.Second)
	manager.observe(key, *rule.HealthCheck, true)
	manager.observe(key, *rule.HealthCheck, false)
	assertSamples(map[string]string{
		"moto_active_health_recovery_successes":                   "0",
		"moto_active_health_last_probe_success_timestamp_seconds": "1788000011.625",
		"moto_active_health_last_recovery_timestamp_seconds":      "1788000001.625",
	})
}

func TestActiveHealthRecoveryDisabledChecksHaveNoConfirmationMetrics(t *testing.T) {
	manager := newActiveHealthManager()
	rule := &config.Rule{Name: "disabled", Targets: []*config.Target{{Address: "upstream:443"}}}
	manager.start(context.Background(), []*config.Rule{rule})
	manager.stop()
	if gauges := snapshotActiveHealthGauges(manager); len(gauges) != 0 {
		t.Fatalf("disabled checker manufactured confirmation state: %+v", gauges)
	}
}

func TestActiveHealthRecoveryKeepsPassiveCircuitAndHTTP3Cooldown(t *testing.T) {
	runtime := newRoutingRuntime()
	defer runtime.stopBackground()
	rule := activeHealthTestRule("independent-health", "upstream:443", config.HealthCheckTCP)
	now := time.Now()
	passiveKey := routeHealthKey{rule: rule.Name, addr: rule.Targets[0].Address}
	passiveState := &routeHealthState{
		ruleName: rule.Name, mode: rule.Mode, circuitOpen: true,
		consecutiveFailures: 3, openUntil: now.Add(time.Minute), lastRecovery: now.Add(-time.Hour),
	}
	runtime.routes.Lock()
	runtime.routes.states[passiveKey] = passiveState
	wantPassive := *passiveState
	runtime.routes.Unlock()
	h3Key := http3ConnectTransportKey{address: rule.Targets[0].Address}
	h3State := &http3FallbackState{failures: 2, retryAt: now.Add(time.Minute), degradationStrikes: 2, degradationActive: true}
	runtime.connectProxy.h3FallbackMu.Lock()
	runtime.connectProxy.h3Fallback[h3Key] = h3State
	wantRetry := h3State.retryAt
	runtime.connectProxy.h3FallbackMu.Unlock()
	key := activeHealthKey{rule: rule, address: rule.Targets[0].Address}
	for _, success := range []bool{false, false, true, true} {
		runtime.health.observe(key, *rule.HealthCheck, success)
	}
	if runtime.health.unhealthy(rule, key.address) {
		t.Fatal("active check did not complete recovery")
	}
	runtime.routes.Lock()
	gotPassive := *runtime.routes.states[passiveKey]
	runtime.routes.Unlock()
	if gotPassive != wantPassive {
		t.Fatal("active recovery changed passive route health")
	}
	runtime.connectProxy.h3FallbackMu.Lock()
	gotH3 := runtime.connectProxy.h3Fallback[h3Key]
	unchanged := gotH3 == h3State && gotH3.failures == 2 && gotH3.retryAt == wantRetry && gotH3.degradationStrikes == 2 && gotH3.degradationActive
	runtime.connectProxy.h3FallbackMu.Unlock()
	if !unchanged {
		t.Fatal("active recovery changed HTTP/3 cooldown")
	}
}
