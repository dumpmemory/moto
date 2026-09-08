package controller

import (
	"context"
	"errors"
	"moto/config"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func newBoostHTTP3RecoveryFixture(t *testing.T) (*routingRuntime, *config.Rule, *config.Target, time.Time) {
	t.Helper()
	runtime := newRoutingRuntime()
	t.Cleanup(runtime.stopBackground)
	now := time.Now()
	runtime.connectProxy.now = func() time.Time { return now }
	target := &config.Target{Address: "recovering.example:443", ConnectProxy: &config.ConnectProxyConfig{Protocols: []string{config.ConnectProxyH3}}}
	sibling := &config.Target{Address: "healthy.example:443", ConnectProxy: &config.ConnectProxyConfig{Protocols: []string{config.ConnectProxyH3}}}
	rule := &config.Rule{Name: t.Name(), Mode: config.ModeBoost, Protocol: config.ProtocolSOCKS5, Timeout: 1000, Targets: []*config.Target{target, sibling}}
	runtime.connectProxy.noteHTTP3Degradation(http3ConnectTransportKey{address: target.Address}, http3DegradationReasonSustainedSignals)
	tripRouteInRegistry(t, runtime.routes, rule, target.Address, now.Add(-routeInitialCooldown-time.Second))
	return runtime, rule, target, now
}

func TestBoostDegradedHTTP3OnlyCircuitGetsCoordinatedRecovery(t *testing.T) {
	runtime, rule, target, now := newBoostHTTP3RecoveryFixture(t)
	lease := runtime.claimBoostRecoveryProbe(rule, now)
	defer runtime.releaseBoostRecoveryProbe(rule, lease)
	if lease.token == 0 || lease.address != target.Address || lease.protocolProbe.token == 0 {
		t.Fatalf("due degraded H3 circuit did not get both recovery leases: %+v", lease)
	}
	var attempts atomic.Int32
	winner, err := runtime.raceBoostTargetsPreparedWithRecovery(context.Background(), rule,
		func(ctx context.Context, address string) (net.Conn, error) {
			attempts.Add(1)
			if address != target.Address || routeProtocolProbeTokenFromContext(ctx) != lease.protocolProbe.token {
				t.Errorf("recovery dial = %q token=%d, want isolated target and its protocol lease", address, routeProtocolProbeTokenFromContext(ctx))
			}
			connection, peer := net.Pipe()
			_ = peer.Close()
			return connection, nil
		}, nil, lease)
	if err != nil {
		t.Fatal(err)
	}
	defer winner.conn.Close()
	if attempts.Load() != 1 || winner.addr != target.Address {
		t.Fatalf("recovery raced healthy sibling: attempts=%d winner=%s", attempts.Load(), winner.addr)
	}
	if state := runtime.routes.snapshot(rule, target.Address, now); state.CircuitOpen {
		t.Fatalf("successful recovery did not close circuit: %+v", state)
	}
}

func TestBoostDegradedHTTP3RecoveryKeepsProtocolRateLimit(t *testing.T) {
	runtime, rule, target, now := newBoostHTTP3RecoveryFixture(t)
	probe, claimed := runtime.routes.claimProtocolProbe(rule, target, now.Add(-10*time.Second))
	if !claimed {
		t.Fatal("fixture protocol canary not claimed")
	}
	runtime.routes.releaseProtocolProbe(rule, target, probe)
	if lease := runtime.claimBoostRecoveryProbe(rule, now); lease.token != 0 {
		runtime.releaseBoostRecoveryProbe(rule, lease)
		t.Fatalf("target recovery bypassed 30-second protocol canary interval: %+v", lease)
	}
	lease := runtime.claimBoostRecoveryProbe(rule, now.Add(http3BoostCanaryInterval))
	defer runtime.releaseBoostRecoveryProbe(rule, lease)
	if lease.token == 0 || lease.protocolProbe.token == 0 {
		t.Fatalf("rate-limited target never became eligible: %+v", lease)
	}
}

func TestBoostDegradedHTTP3RecoveryHasOneConcurrentOwner(t *testing.T) {
	runtime, rule, target, now := newBoostHTTP3RecoveryFixture(t)
	const callers = 32
	leases := make(chan routeRecoveryLease, callers)
	var workers sync.WaitGroup
	for range callers {
		workers.Add(1)
		go func() { defer workers.Done(); leases <- runtime.claimBoostRecoveryProbe(rule, now) }()
	}
	workers.Wait()
	close(leases)
	owners := 0
	var owner routeRecoveryLease
	for lease := range leases {
		if lease.token != 0 {
			owners++
			owner = lease
		}
	}
	defer runtime.releaseBoostRecoveryProbe(rule, owner)
	if owners != 1 || owner.address != target.Address || owner.protocolProbe.token == 0 {
		t.Fatalf("concurrent recovery owners=%d lease=%+v", owners, owner)
	}
	if probe, claimed := runtime.routes.claimProtocolProbe(rule, target, now.Add(time.Minute)); claimed {
		runtime.routes.releaseProtocolProbe(rule, target, probe)
		t.Fatal("ordinary protocol canary stole the active recovery owner's lease")
	}
}

func TestBoostDegradedHTTP3RecoveryCancellationReleasesOwnership(t *testing.T) {
	runtime, rule, target, now := newBoostHTTP3RecoveryFixture(t)
	lease := runtime.claimBoostRecoveryProbe(rule, now)
	if lease.token == 0 || lease.protocolProbe.token == 0 {
		t.Fatalf("missing recovery lease: %+v", lease)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	started := make(chan struct{})
	go func() { <-started; cancel() }()
	_, err := runtime.raceBoostTargetsPreparedWithRecovery(ctx, rule,
		func(ctx context.Context, address string) (net.Conn, error) {
			if address != target.Address {
				return nil, errors.New("unexpected sibling")
			}
			close(started)
			<-ctx.Done()
			return nil, ctx.Err()
		}, nil, lease)
	runtime.releaseBoostRecoveryProbe(rule, lease)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled recovery=%v", err)
	}
	state := runtime.routes.snapshot(rule, target.Address, now)
	if state.HalfOpen || state.ConsecutiveFailures != routeFailureThreshold {
		t.Fatalf("cancellation mutated circuit failures or retained half-open: %+v", state)
	}
	next := runtime.claimBoostRecoveryProbe(rule, now.Add(http3BoostCanaryInterval+time.Second))
	defer runtime.releaseBoostRecoveryProbe(rule, next)
	if next.token == 0 || next.protocolProbe.token == 0 {
		t.Fatalf("cancellation leaked recovery ownership: %+v", next)
	}
}

func TestBoostDegradedHTTP3RecoveryCannotBypassRulePolicyAfterCapacityWait(t *testing.T) {
	for _, phase := range []string{"cooldown", "probation", "due", "evaluating"} {
		t.Run(phase, func(t *testing.T) {
			runtime, rule, target, now := newBoostHTTP3RecoveryFixture(t)
			mixed := rule.Targets[1]
			mixed.ConnectProxy.Protocols = []string{config.ConnectProxyH3, config.ConnectProxyH2}
			lease := runtime.claimBoostRecoveryProbe(rule, now)
			defer runtime.releaseBoostRecoveryProbe(rule, lease)
			if lease.token == 0 || lease.protocolProbe.token == 0 {
				t.Fatalf("missing pre-transition recovery lease: %+v", lease)
			}
			var blockedCalls atomic.Int32
			var releases atomic.Int32
			acquire := func(_ context.Context, _ *config.Rule, address string, _ bool) (boostDialRelease, error) {
				if address == target.Address {
					_ = openHTTP3RuleCooldownForTest(t, runtime.connectProxy, rule.Name, mixed)
					if phase != "cooldown" {
						runtime.connectProxy.h3RuleBreaker.mu.Lock()
						state := runtime.connectProxy.h3RuleBreaker.rules[rule.Name]
						switch phase {
						case "probation":
							state.phase = http3RuleBreakerProbation
							state.probation = http3RuleProbationState{token: 91, key: http3ConnectTransportKey{address: mixed.Address}}
						case "due":
							state.retryAt = now.Add(-time.Second)
						case "evaluating":
							state.phase = http3RuleBreakerEvaluating
							state.evaluationToken = 91
						}
						runtime.connectProxy.h3RuleBreaker.mu.Unlock()
					}
				}
				return func() { releases.Add(1) }, nil
			}
			winner, err := runtime.raceBoostTargetsPreparedWithAdmissionAndRecovery(context.Background(), rule,
				func(_ context.Context, address string) (net.Conn, error) {
					if address == target.Address {
						blockedCalls.Add(1)
						return nil, errors.New("H3 recovery bypassed newly committed rule policy")
					}
					connection, peer := net.Pipe()
					_ = peer.Close()
					return connection, nil
				}, nil, acquire, lease)
			if err != nil {
				t.Fatal(err)
			}
			defer winner.conn.Close()
			if blockedCalls.Load() != 0 || winner.addr != mixed.Address || releases.Load() != 2 {
				t.Fatalf("post-admission policy bypass: H3Calls=%d winner=%s permitsReleased=%d", blockedCalls.Load(), winner.addr, releases.Load())
			}
			if state := runtime.routes.snapshot(rule, target.Address, now); state.HalfOpen || state.ConsecutiveFailures != routeFailureThreshold {
				t.Fatalf("policy rejection consumed a route attempt: %+v", state)
			}
		})
	}
}

func TestBoostDegradedHTTP3RecoveryStillHonorsGlobalDialCapacity(t *testing.T) {
	runtime, rule, _, now := newBoostHTTP3RecoveryFixture(t)
	lease := runtime.claimBoostRecoveryProbe(rule, now)
	defer runtime.releaseBoostRecoveryProbe(rule, lease)
	if lease.token == 0 {
		t.Fatal("missing recovery lease")
	}
	var dials atomic.Int32
	_, err := runtime.raceBoostTargetsPreparedWithAdmissionAndRecovery(context.Background(), rule,
		func(context.Context, string) (net.Conn, error) {
			dials.Add(1)
			return nil, errors.New("unexpected network dial")
		}, nil,
		func(context.Context, *config.Rule, string, bool) (boostDialRelease, error) {
			return nil, &dialBulkheadError{saturated: true, scope: dialSaturationGlobal}
		}, lease)
	if !isDialBulkheadError(err) || dials.Load() != 0 {
		t.Fatalf("global capacity bypass: err=%v dials=%d", err, dials.Load())
	}
}

func TestBoostDegradedHTTP3RecoveryCannotStealExistingProtocolCanary(t *testing.T) {
	runtime, rule, target, now := newBoostHTTP3RecoveryFixture(t)
	probe, claimed := runtime.routes.claimProtocolProbe(rule, target, now)
	if !claimed {
		t.Fatal("fixture protocol canary not claimed")
	}
	defer runtime.routes.releaseProtocolProbe(rule, target, probe)
	if lease := runtime.claimBoostRecoveryProbe(rule, now.Add(time.Minute)); lease.token != 0 {
		runtime.releaseBoostRecoveryProbe(rule, lease)
		t.Fatalf("target recovery stole protocol canary: %+v", lease)
	}
	runtime.routes.releaseProtocolProbe(rule, target, probe)
	lease := runtime.claimBoostRecoveryProbe(rule, now.Add(time.Minute+routeRecoveryProbeInterval))
	defer runtime.releaseBoostRecoveryProbe(rule, lease)
	if lease.token == 0 || lease.protocolProbe.token == 0 {
		t.Fatalf("released canary remained unavailable: %+v", lease)
	}
}

func TestBoostDegradedHTTP3RecoveryCannotStealExistingHalfOpenAttempt(t *testing.T) {
	runtime, rule, target, now := newBoostHTTP3RecoveryFixture(t)
	lease := runtime.claimBoostRecoveryProbe(rule, now)
	defer runtime.releaseBoostRecoveryProbe(rule, lease)
	if lease.token == 0 || lease.protocolProbe.token == 0 {
		t.Fatalf("missing recovery lease: %+v", lease)
	}
	owner, err := runtime.routes.begin(rule, target.Address, now)
	if err != nil {
		t.Fatal(err)
	}
	defer routeObserve(owner, 0, context.Canceled, now)
	var forbidden atomic.Int32
	winner, err := runtime.raceBoostTargetsPreparedWithRecovery(context.Background(), rule,
		func(_ context.Context, address string) (net.Conn, error) {
			if address == target.Address {
				forbidden.Add(1)
			}
			connection, peer := net.Pipe()
			_ = peer.Close()
			return connection, nil
		}, nil, lease)
	if err != nil {
		t.Fatal(err)
	}
	defer winner.conn.Close()
	if forbidden.Load() != 0 || winner.addr == target.Address {
		t.Fatalf("recovery bypassed half-open owner: forbidden=%d winner=%s", forbidden.Load(), winner.addr)
	}
	if state := runtime.routes.snapshot(rule, target.Address, now); !state.HalfOpen {
		t.Fatalf("rejected recovery released another attempt's half-open ownership: %+v", state)
	}
}
