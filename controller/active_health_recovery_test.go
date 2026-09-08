package controller

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"reflect"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"moto/config"
)

func TestActiveHealthRecoveryCadence(t *testing.T) {
	const normal = 10 * time.Second
	const fast = 1500 * time.Millisecond
	tests := []struct {
		name      string
		checkType string
		interval  time.Duration
		threshold int
		outcomes  []bool
		delays    []time.Duration
		unhealthy []bool
		progress  []int
	}{
		{
			name: "healthy failure and confirmed recovery", checkType: config.HealthCheckTCP, interval: normal, threshold: 2,
			outcomes:  []bool{true, false, false, true, true, true},
			delays:    []time.Duration{normal, normal, normal, fast, normal, normal},
			unhealthy: []bool{false, false, true, true, false, false}, progress: []int{0, 0, 0, 1, 0, 0},
		},
		{
			name: "failed second confirmation and flapping", checkType: config.HealthCheckTCP, interval: normal, threshold: 2,
			outcomes:  []bool{false, false, true, false, true, false, true, true},
			delays:    []time.Duration{normal, normal, fast, normal, fast, normal, fast, normal},
			unhealthy: []bool{false, true, true, true, true, true, true, false}, progress: []int{0, 0, 1, 0, 1, 0, 1, 0},
		},
		{
			name: "HTTP retains normal interval", checkType: config.HealthCheckHTTP, interval: normal, threshold: 2,
			outcomes: []bool{false, false, true, true}, delays: []time.Duration{normal, normal, normal, normal},
			unhealthy: []bool{false, true, true, false}, progress: []int{0, 0, 1, 0},
		},
		{
			name: "short interval never slows", checkType: config.HealthCheckTCP, interval: 250 * time.Millisecond, threshold: 2,
			outcomes:  []bool{false, false, true, true},
			delays:    []time.Duration{250 * time.Millisecond, 250 * time.Millisecond, 250 * time.Millisecond, 250 * time.Millisecond},
			unhealthy: []bool{false, true, true, false}, progress: []int{0, 0, 1, 0},
		},
		{
			name: "one success immediately recovers", checkType: config.HealthCheckTCP, interval: normal, threshold: 1,
			outcomes: []bool{false, false, true}, delays: []time.Duration{normal, normal, normal},
			unhealthy: []bool{false, true, false}, progress: []int{0, 0, 0},
		},
		{
			name: "only second of four confirmations accelerates", checkType: config.HealthCheckTCP, interval: normal, threshold: 4,
			outcomes:  []bool{false, false, true, true, true, true},
			delays:    []time.Duration{normal, normal, fast, normal, normal, normal},
			unhealthy: []bool{false, true, true, true, true, false}, progress: []int{0, 0, 1, 2, 3, 0},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			rule := activeHealthTestRule("cadence", "fixture:443", test.checkType)
			rule.HealthCheck.Interval = uint64(test.interval / time.Millisecond)
			rule.HealthCheck.SuccessThreshold = test.threshold
			manager := newActiveHealthManager()
			manager.nextDelay = func(base time.Duration) time.Duration { return base }
			job := activeHealthJob{key: activeHealthKey{rule: rule, address: "fixture:443"}, check: *rule.HealthCheck}
			for index, success := range test.outcomes {
				manager.observe(job.key, job.check, success)
				if got := manager.nextProbeDelay(job, test.interval); got != test.delays[index] {
					t.Errorf("probe %d delay = %v, want %v", index+1, got, test.delays[index])
				}
				gauge := snapshotActiveHealthGauges(manager)[0]
				if gauge.unhealthy != test.unhealthy[index] || gauge.recoverySuccesses != test.progress[index] {
					t.Errorf("probe %d unhealthy/progress = %v/%d, want %v/%d", index+1, gauge.unhealthy, gauge.recoverySuccesses, test.unhealthy[index], test.progress[index])
				}
			}
		})
	}
}

func TestActiveHealthRecoveryDelayUsesExistingJitter(t *testing.T) {
	rule := activeHealthTestRule("jitter", "fixture:443", config.HealthCheckTCP)
	manager := newActiveHealthManager()
	key := activeHealthKey{rule: rule, address: "fixture:443"}
	manager.states[key] = &activeHealthState{unhealthy: true, consecutiveSuccesses: 1}
	job := activeHealthJob{key: key, check: *rule.HealthCheck}
	for _, interval := range []time.Duration{250 * time.Millisecond, 1500 * time.Millisecond, 10 * time.Second} {
		base := min(interval, activeHealthRecoveryConfirmCap)
		spread := base * activeHealthJitterPercent / 100
		for index := 0; index < 100; index++ {
			if got := manager.nextProbeDelay(job, interval); got < base-spread || got > base+spread {
				t.Fatalf("interval %v jittered delay = %v, want [%v,%v]", interval, got, base-spread, base+spread)
			}
		}
	}
}

// Drives the real checker loop with a clock advanced only by scheduled waits
// and completed probes, making timestamp and cadence assertions deterministic.
func TestActiveHealthRecoveryCheckerScheduleAndTimestamps(t *testing.T) {
	rule := activeHealthTestRule("clock", "fixture:443", config.HealthCheckTCP)
	rule.HealthCheck.Interval = 10_000
	manager := newActiveHealthManager()
	key := activeHealthKey{rule: rule, address: "fixture:443"}
	manager.states[key] = &activeHealthState{requiredSuccesses: 2}
	now := time.Unix(1_788_000_000, 0)
	manager.now = func() time.Time { return now }
	manager.initialDelay = func(time.Duration) time.Duration { return 400 * time.Millisecond }
	manager.nextDelay = func(base time.Duration) time.Duration { return base }
	outcomes := []bool{false, false, true, true, true}
	var delays []time.Duration
	var successes []time.Time
	var recoveredAt time.Time
	probes := 0
	manager.waitDelay = func(_ context.Context, delay time.Duration) bool {
		delays = append(delays, delay)
		gauge := snapshotActiveHealthGauges(manager)[0]
		if gauge.nextProbeAt != now.Add(delay) || gauge.probeInFlight {
			t.Fatalf("waiting probe: next=%v, now=%v delay=%v, in flight=%v", gauge.nextProbeAt, now, delay, gauge.probeInFlight)
		}
		if probes > 0 {
			var lastSuccess time.Time
			if len(successes) > 0 {
				lastSuccess = successes[len(successes)-1]
			}
			if gauge.lastProbeSuccess != lastSuccess || gauge.lastRecovery != recoveredAt {
				t.Fatalf("probe %d timestamps: success=%v recovery=%v, want %v/%v", probes, gauge.lastProbeSuccess, gauge.lastRecovery, lastSuccess, recoveredAt)
			}
		}
		if probes == len(outcomes) {
			return false
		}
		now = now.Add(delay)
		return true
	}
	manager.probe = func(context.Context, string, config.HealthCheckConfig, string) error {
		gauge := snapshotActiveHealthGauges(manager)[0]
		if !gauge.probeInFlight || !gauge.nextProbeAt.IsZero() {
			t.Fatal("running probe did not expose in-flight=1 and next=0")
		}
		now = now.Add(125 * time.Millisecond)
		success := outcomes[probes]
		probes++
		if success {
			successes = append(successes, now)
			if probes == 4 {
				recoveredAt = now
			}
			return nil
		}
		return errors.New("controlled probe failure")
	}
	manager.wg.Add(1)
	manager.runChecker(context.Background(), activeHealthJob{key: key, target: key.address, check: *rule.HealthCheck, failureConclusive: true})
	wantDelays := []time.Duration{400 * time.Millisecond, 10 * time.Second, 10 * time.Second, 1500 * time.Millisecond, 10 * time.Second, 10 * time.Second}
	if !reflect.DeepEqual(delays, wantDelays) {
		t.Fatalf("delays = %v, want %v", delays, wantDelays)
	}
	gauge := snapshotActiveHealthGauges(manager)[0]
	if gauge.unhealthy || gauge.recoverySuccesses != 0 || !gauge.nextProbeAt.IsZero() || gauge.probeInFlight {
		t.Fatalf("stopped recovered checker gauge = %+v", gauge)
	}
}

func TestActiveHealthRecoveryCancellationPreservesConfirmationEvidence(t *testing.T) {
	for _, cancelDuringProbe := range []bool{false, true} {
		t.Run(fmt.Sprintf("inflight=%v", cancelDuringProbe), func(t *testing.T) {
			rule := activeHealthTestRule("cancel-recovery", "fixture:443", config.HealthCheckTCP)
			manager := newActiveHealthManager()
			key := activeHealthKey{rule: rule, address: "fixture:443"}
			lastSuccess := time.Unix(1_788_000_000, 0)
			manager.states[key] = &activeHealthState{unhealthy: true, consecutiveSuccesses: 1, requiredSuccesses: 2, lastProbeSuccess: lastSuccess}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			manager.waitDelay = func(context.Context, time.Duration) bool {
				if !cancelDuringProbe {
					cancel()
					return false
				}
				return true
			}
			manager.probe = func(context.Context, string, config.HealthCheckConfig, string) error {
				cancel()
				return nil // A success returned after cancellation is not evidence.
			}
			manager.wg.Add(1)
			manager.runChecker(ctx, activeHealthJob{key: key, check: *rule.HealthCheck, failureConclusive: true})
			gauge := snapshotActiveHealthGauges(manager)[0]
			if !gauge.unhealthy || gauge.recoverySuccesses != 1 || gauge.lastProbeSuccess != lastSuccess || !gauge.lastRecovery.IsZero() || !gauge.nextProbeAt.IsZero() || gauge.probeInFlight {
				t.Fatalf("canceled checker changed evidence or retained schedule: %+v", gauge)
			}
		})
	}
}

func TestActiveHealthRecoverySharesCapacityAcrossGenerations(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var managers []*activeHealthManager
	defer func() {
		cancel()
		for _, manager := range managers {
			manager.stop()
		}
	}()
	var attempts sync.Map
	var current atomic.Int64
	var peak atomic.Int64
	var once sync.Once
	reachedLimit := make(chan struct{})
	for generation := 0; generation < 2; generation++ {
		rule := activeHealthTestRule(fmt.Sprintf("generation-%d", generation), "fixture:443", config.HealthCheckTCP)
		rule.HealthCheck.Interval = 10_000
		rule.HealthCheck.Timeout = 30_000
		rule.Targets = nil
		manager := newActiveHealthManager()
		managers = append(managers, manager)
		manager.initialDelay = func(time.Duration) time.Duration { return 0 }
		manager.nextDelay = func(base time.Duration) time.Duration {
			if base != activeHealthRecoveryConfirmCap {
				t.Errorf("second confirmation base = %v, want %v", base, activeHealthRecoveryConfirmCap)
			}
			return 0
		}
		for target := 0; target < activeHealthMaxConcurrentProbes; target++ {
			address := fmt.Sprintf("generation-%d-target-%d:443", generation, target)
			rule.Targets = append(rule.Targets, &config.Target{Address: address})
			manager.states[activeHealthKey{rule: rule, address: address}] = &activeHealthState{unhealthy: true}
		}
		manager.probe = func(ctx context.Context, address string, _ config.HealthCheckConfig, _ string) error {
			if _, loaded := attempts.LoadOrStore(address, true); !loaded {
				return nil // The first recovery success schedules fast confirmation.
			}
			active := current.Add(1)
			defer current.Add(-1)
			for previous := peak.Load(); active > previous && !peak.CompareAndSwap(previous, active); previous = peak.Load() {
			}
			if active == activeHealthMaxConcurrentProbes {
				once.Do(func() { close(reachedLimit) })
			}
			<-ctx.Done()
			return ctx.Err()
		}
		manager.start(ctx, []*config.Rule{rule})
	}
	select {
	case <-reachedLimit:
	case <-time.After(3 * time.Second):
		t.Fatalf("fast recovery confirmations did not fill capacity; peak=%d", peak.Load())
	}
	if got := peak.Load(); got != activeHealthMaxConcurrentProbes {
		t.Fatalf("confirmation concurrency = %d, want shared maximum %d", got, activeHealthMaxConcurrentProbes)
	}
	inFlight := 0
	for _, manager := range managers {
		for _, gauge := range snapshotActiveHealthGauges(manager) {
			if gauge.probeInFlight {
				inFlight++
				if !gauge.nextProbeAt.IsZero() {
					t.Fatal("in-flight confirmation retained a next-probe timestamp")
				}
			}
		}
	}
	if inFlight != activeHealthMaxConcurrentProbes {
		t.Fatalf("in-flight metrics = %d, want %d", inFlight, activeHealthMaxConcurrentProbes)
	}
	cancel()
	for _, manager := range managers {
		manager.stop()
		for _, gauge := range snapshotActiveHealthGauges(manager) {
			if gauge.probeInFlight || !gauge.nextProbeAt.IsZero() || !gauge.lastRecovery.IsZero() || !gauge.unhealthy {
				t.Fatalf("canceled fast confirmation changed recovery or retained scheduling: %+v", gauge)
			}
		}
	}
	if current.Load() != 0 || len(activeHealthProbeSlots) != 0 {
		t.Fatal("canceling recovery generations leaked global probe capacity")
	}
}

func TestActiveHealthRecoveryReloadResetsInheritedInFlightState(t *testing.T) {
	previous := newRoutingRuntime()
	defer previous.stopBackground()
	current := newRoutingRuntime()
	defer current.stopBackground()
	oldRule := activeHealthTestRule("reload-recovery", "fixture:443", config.HealthCheckTCP)
	oldRule.HealthCheck.Timeout = 30_000
	newRuleValue := *oldRule
	newRule := &newRuleValue
	oldKey := activeHealthKey{rule: oldRule, address: oldRule.Targets[0].Address}
	lastSuccess := time.Unix(1_788_000_000, 125_000_000)
	lastRecovery := lastSuccess.Add(-time.Hour)
	previous.health.states[oldKey] = &activeHealthState{
		unhealthy: true, consecutiveSuccesses: 1, requiredSuccesses: 2,
		lastProbeSuccess: lastSuccess, lastRecovery: lastRecovery,
	}
	previous.health.initialDelay = func(time.Duration) time.Duration { return 0 }
	oldProbeStarted := make(chan struct{})
	previous.health.probe = func(ctx context.Context, _ string, _ config.HealthCheckConfig, _ string) error {
		close(oldProbeStarted)
		<-ctx.Done()
		return ctx.Err()
	}
	previous.health.start(context.Background(), []*config.Rule{oldRule})
	select {
	case <-oldProbeStarted:
	case <-time.After(2 * time.Second):
		t.Fatal("old generation probe did not start")
	}
	current.inheritUnchangedState(previous, []*config.Rule{oldRule}, []*config.Rule{newRule})
	inherited := snapshotActiveHealthGauges(current.health)
	if len(inherited) != 1 || !inherited[0].probeInFlight {
		t.Fatalf("fixture did not inherit the old in-flight state: %+v", inherited)
	}
	now := lastSuccess.Add(time.Second)
	current.health.now = func() time.Time { return now }
	current.health.initialDelay = func(time.Duration) time.Duration { return 3 * time.Second }
	newWaiting := make(chan activeHealthGauge, 1)
	current.health.waitDelay = func(ctx context.Context, _ time.Duration) bool {
		newWaiting <- snapshotActiveHealthGauges(current.health)[0]
		<-ctx.Done()
		return false
	}
	var newProbes atomic.Int64
	current.health.probe = func(context.Context, string, config.HealthCheckConfig, string) error {
		newProbes.Add(1)
		return nil
	}
	current.health.start(context.Background(), []*config.Rule{newRule})
	select {
	case gauge := <-newWaiting:
		if gauge.probeInFlight || gauge.nextProbeAt != now.Add(3*time.Second) || newProbes.Load() != 0 {
			t.Fatalf("new checker inherited probe ownership or schedule: %+v, probes=%d", gauge, newProbes.Load())
		}
		if !gauge.unhealthy || gauge.recoverySuccesses != 1 || gauge.requiredSuccesses != 2 || gauge.lastProbeSuccess != lastSuccess || gauge.lastRecovery != lastRecovery {
			t.Fatalf("new generation discarded confirmation evidence: %+v", gauge)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("new generation did not enter its initial timer wait")
	}
	if oldGauge := snapshotActiveHealthGauges(previous.health)[0]; !oldGauge.probeInFlight {
		t.Fatal("starting new generation changed the old probe's ownership")
	}
}

func TestActiveHealthRecoveryRealClockAB(t *testing.T) {
	if os.Getenv("MOTO_ACTIVE_HEALTH_REAL_CLOCK_AB") != "1" {
		t.Skip("set MOTO_ACTIVE_HEALTH_REAL_CLOCK_AB=1 to compare real TCP confirmation intervals (about 12 seconds)")
	}
	const interval = 10 * time.Second
	results := make(map[string]time.Duration)
	for _, policy := range []string{"previous", "optimized"} {
		t.Run(policy, func(t *testing.T) {
			listener, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			address := listener.Addr().String()
			_ = listener.Close() // Real refused TCP connections establish unhealthy.
			defer func() {
				if listener != nil {
					_ = listener.Close()
				}
			}()
			rule := activeHealthTestRule("real-clock-ab", address, config.HealthCheckTCP)
			rule.HealthCheck.Interval = uint64(interval / time.Millisecond)
			manager := newActiveHealthManager()
			key := activeHealthKey{rule: rule, address: address}
			manager.states[key] = &activeHealthState{requiredSuccesses: 2}
			manager.initialDelay = func(time.Duration) time.Duration { return 0 }
			probes := 0
			var successes []time.Time
			manager.probe = func(ctx context.Context, address string, check config.HealthCheckConfig, protocol string) error {
				err := probeActiveHealthTarget(ctx, address, check, protocol)
				probes++
				if probes <= 2 && err == nil {
					t.Fatal("closed TCP fixture unexpectedly accepted an outage probe")
				}
				if probes > 2 {
					if err != nil {
						t.Fatalf("restored TCP fixture: %v", err)
					}
					successes = append(successes, time.Now())
				}
				return err
			}
			manager.nextDelay = func(base time.Duration) time.Duration {
				if probes == 2 {
					if !manager.unhealthy(rule, address) {
						t.Fatal("two failed TCP probes did not reach the unchanged failure threshold")
					}
					listener, err = net.Listen("tcp", address)
					if err != nil {
						t.Fatal(err)
					}
					go func(listener net.Listener) {
						for {
							connection, err := listener.Accept()
							if err != nil {
								return
							}
							_ = connection.Close()
						}
					}(listener)
				}
				if probes <= 2 {
					return 0 // Compress only fixture outage setup and restoration.
				}
				if policy == "previous" {
					return interval // Test-only restoration of the prior scheduling policy.
				}
				return base // Remove jitter equally in both arms for direct comparison.
			}
			manager.waitDelay = func(ctx context.Context, delay time.Duration) bool {
				if len(successes) == 2 {
					return false
				}
				return waitActiveHealthDelay(ctx, delay)
			}
			ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
			defer cancel()
			manager.wg.Add(1)
			manager.runChecker(ctx, activeHealthJob{key: key, target: address, check: *rule.HealthCheck, failureConclusive: true})
			if len(successes) != 2 || manager.unhealthy(rule, address) {
				t.Fatalf("successful probes = %d; target did not recover", len(successes))
			}
			gap := successes[1].Sub(successes[0])
			want := interval
			if policy == "optimized" {
				want = activeHealthRecoveryConfirmCap
			}
			if gap < want || gap > want+2*time.Second {
				t.Fatalf("confirmation gap = %v, want [%v,%v]", gap, want, want+2*time.Second)
			}
			results[policy] = gap
			t.Logf("policy=%s interval_ms=%d failure_threshold=2 success_threshold=2 tcp_failures=2 tcp_successes=2 confirmation_gap_ms=%.3f", policy, interval.Milliseconds(), float64(gap)/float64(time.Millisecond))
		})
	}
	if len(results) == 2 {
		t.Logf("confirmation time saved = %v", results["previous"]-results["optimized"])
	}
}
