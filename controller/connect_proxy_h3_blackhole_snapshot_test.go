package controller

import (
	"context"
	"moto/config"
	"net"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestHTTP3UDPBlackholeSnapshotJoinProtectsBothBlockedStreams(t *testing.T) {
	for _, test := range []struct {
		name           string
		concurrent     bool
		firstRecovered bool
	}{
		{name: "join_before_snapshot"},
		{name: "join_after_snapshot", concurrent: true},
		{name: "all_snapshot_generations_recovered_after_new_join", concurrent: true, firstRecovered: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			manager := newConnectProxyManager()
			t.Cleanup(manager.close)
			now := time.Now()
			manager.now = func() time.Time { return now }
			manager.h3.now = func() time.Time { return now }
			first := prepareHTTP3BlackholeEvent(t, manager, "snapshot", mixedHTTP3BlackholeTarget("first.example:443"), "destination.example:443", 2001)
			second := prepareHTTP3BlackholeEvent(t, manager, "snapshot", mixedHTTP3BlackholeTarget("second.example:443"), "destination.example:443", 2002)
			firstStream := h3BlackholeSnapshotBlockedStream(t, manager.h3, first)
			secondStream := h3BlackholeSnapshotBlockedStream(t, manager.h3, second)

			dialStarted := make(chan struct{})
			releaseDial := make(chan struct{})
			var releaseOnce sync.Once
			unblockDial := func() { releaseOnce.Do(func() { close(releaseDial) }) }
			t.Cleanup(unblockDial)
			var h2Calls atomic.Int64
			manager.dialers[config.ConnectProxyH2] = func(ctx context.Context, _ *config.Target, _ string) (net.Conn, error) {
				if h2Calls.Add(1) == 1 {
					close(dialStarted)
				}
				select {
				case <-releaseDial:
				case <-ctx.Done():
					return nil, ctx.Err()
				}
				connection, peer := net.Pipe()
				_ = peer.Close()
				return connection, nil
			}
			manager.noteHTTP3UDPBlackhole(first)
			select {
			case <-dialStarted:
			case <-time.After(time.Second):
				t.Fatal("blackhole validation did not reach H2 dial")
			}

			if test.concurrent {
				// The real validator's second snapshot contains only A. Hold H3.mu
				// until its stack confirms generation validation is waiting on it;
				// B's notification then joins under the independent breaker lock.
				manager.h3.mu.Lock()
				unblockDial()
				if !h3BlackholeSnapshotValidatorWaiting() {
					manager.h3.mu.Unlock()
					t.Fatal("validator did not wait on H3 lock after reading snapshot")
				}
				manager.noteHTTP3UDPBlackhole(second)
				if test.firstRecovered {
					// A's physical generation has been replaced while B joined.
					// Every checked snapshot member is now stale, but B still owns
					// valid work and must keep this H2 evaluation alive.
					first.slot.connectionID++
					first.slot.health = http3TransportHealthy
					first.slot.rotationReason = http3DegradationReasonNone
				}
				manager.h3RuleBreaker.mu.Lock()
				joined := len(manager.h3RuleBreaker.rules["snapshot"].evaluationBlackholes)
				manager.h3RuleBreaker.mu.Unlock()
				manager.h3.mu.Unlock()
				if joined != 2 {
					t.Fatalf("scopes before snapshot merge = %d, want 2", joined)
				}
			} else {
				manager.noteHTTP3UDPBlackhole(second)
				unblockDial()
			}

			done := make(chan struct{})
			go func() { manager.maintenanceWG.Wait(); close(done) }()
			select {
			case <-done:
			case <-time.After(2 * time.Second):
				t.Fatal("H2 validation did not complete")
			}
			manager.h3.mu.Lock()
			firstMonitor := first.slot.forcedDrainMonitor
			secondMonitor := second.slot.forcedDrainMonitor
			manager.h3.mu.Unlock()
			if h2Calls.Load() != 1 || blackholeRulePhase(manager, "snapshot") != http3RuleBreakerCooldown || (firstMonitor == nil) != test.firstRecovered || secondMonitor == nil {
				t.Fatalf("validated drains = H2:%d A:%t B:%t recovered-A:%t", h2Calls.Load(), firstMonitor != nil, secondMonitor != nil, test.firstRecovered)
			}
			// Each monitor checked its first sample when it was armed. The next
			// check must call the production fast-fail hooks for both old streams.
			checkAt := now.Add(http3DegradationSampleInterval)
			manager.h3.checkHTTP3ForcedDrainAt(firstMonitor, checkAt)
			manager.h3.checkHTTP3ForcedDrainAt(secondMonitor, checkAt)
			if test.firstRecovered {
				if firstStream.canceled.Load() != 0 {
					t.Fatal("late H2 validation fast-failed recovered A generation")
				}
			} else {
				h3BlackholeSnapshotStreamReleased(t, firstStream)
			}
			h3BlackholeSnapshotStreamReleased(t, secondStream)
		})
	}
}

func TestHTTP3UDPBlackholeSnapshotPrunesOnlyEvaluatedScopes(t *testing.T) {
	for _, firstActive := range []bool{false, true} {
		name := "all_evaluated_stale_new_member_survives"
		if firstActive {
			name = "active_and_new_members_survive"
		}
		t.Run(name, func(t *testing.T) {
			breaker, first, second := h3BlackholeSnapshotBreaker()
			token, claimed, _ := breaker.beginUDPBlackholeValidation("snapshot", first)
			if !claimed {
				t.Fatal("initial probe was not claimed")
			}
			evaluated := breaker.udpBlackholeEvaluationScopes("snapshot", token)
			for range 2 {
				joinedToken, joinedClaim, _ := breaker.beginUDPBlackholeValidation("snapshot", second)
				if joinedToken != token || joinedClaim {
					t.Fatal("duplicate new member did not join the one validation")
				}
			}
			var active []http3UDPBlackholeScope
			want := []http3UDPBlackholeScope{second}
			if firstActive {
				active = []http3UDPBlackholeScope{first}
				want = []http3UDPBlackholeScope{first, second}
			}
			if !breaker.retainUDPBlackholeEvaluationScopes("snapshot", token, evaluated, active) {
				t.Fatal("new live member was erased by older snapshot")
			}
			h3BlackholeSnapshotAssertScopes(t, breaker.udpBlackholeEvaluationScopes("snapshot", token), want)
			if result := breaker.completeUDPBlackholeValidation("snapshot", token, true); result != http3UDPBlackholeValidationCommitted {
				t.Fatalf("H2 validation result = %d, want committed", result)
			}
			h3BlackholeSnapshotAssertScopes(t, breaker.takeCommittedUDPBlackholes("snapshot"), want)
		})
	}
}

func TestHTTP3UDPBlackholeSnapshotCannotResurrectPrunedMember(t *testing.T) {
	breaker, first, second := h3BlackholeSnapshotBreaker()
	token, _, _ := breaker.beginUDPBlackholeValidation("snapshot", first)
	breaker.beginUDPBlackholeValidation("snapshot", second)
	evaluated := breaker.udpBlackholeEvaluationScopes("snapshot", token)
	if !breaker.retainUDPBlackholeEvaluationScopes("snapshot", token, evaluated, []http3UDPBlackholeScope{first}) {
		t.Fatal("newer snapshot incorrectly discarded A")
	}
	// An earlier check still considers B active. It may retain current members
	// but must not append B back after a newer check has proved it stale.
	if !breaker.retainUDPBlackholeEvaluationScopes("snapshot", token, evaluated, evaluated) {
		t.Fatal("older snapshot incorrectly discarded A")
	}
	h3BlackholeSnapshotAssertScopes(t, breaker.udpBlackholeEvaluationScopes("snapshot", token), []http3UDPBlackholeScope{first})
}

func TestHTTP3UDPBlackholeSnapshotCannotRemoveNewPhysicalGeneration(t *testing.T) {
	breaker, old, _ := h3BlackholeSnapshotBreaker()
	token, _, _ := breaker.beginUDPBlackholeValidation("snapshot", old)
	evaluated := breaker.udpBlackholeEvaluationScopes("snapshot", token)
	newGeneration := old
	newGeneration.connectionID++
	breaker.beginUDPBlackholeValidation("snapshot", newGeneration)
	if !breaker.retainUDPBlackholeEvaluationScopes("snapshot", token, evaluated, nil) {
		t.Fatal("old generation result erased newly joined generation")
	}
	h3BlackholeSnapshotAssertScopes(t, breaker.udpBlackholeEvaluationScopes("snapshot", token), []http3UDPBlackholeScope{newGeneration})
}

func TestHTTP3UDPBlackholeSnapshotCannotMutateNewEvaluationToken(t *testing.T) {
	breaker, first, second := h3BlackholeSnapshotBreaker()
	oldToken, _, _ := breaker.beginUDPBlackholeValidation("snapshot", first)
	evaluated := breaker.udpBlackholeEvaluationScopes("snapshot", oldToken)
	breaker.abandonUDPBlackholeProbe("snapshot", oldToken)
	newToken, claimed, _ := breaker.beginUDPBlackholeValidation("snapshot", second)
	if !claimed || newToken == oldToken {
		t.Fatal("new evaluation was not created")
	}
	if breaker.retainUDPBlackholeEvaluationScopes("snapshot", oldToken, evaluated, evaluated) {
		t.Fatal("stale snapshot accepted a newer evaluation token")
	}
	h3BlackholeSnapshotAssertScopes(t, breaker.udpBlackholeEvaluationScopes("snapshot", newToken), []http3UDPBlackholeScope{second})
}

func TestHTTP3UDPBlackholeSnapshotAllStaleStillAbandonsEvaluation(t *testing.T) {
	breaker, first, _ := h3BlackholeSnapshotBreaker()
	token, _, _ := breaker.beginUDPBlackholeValidation("snapshot", first)
	evaluated := breaker.udpBlackholeEvaluationScopes("snapshot", token)
	if breaker.retainUDPBlackholeEvaluationScopes("snapshot", token, evaluated, nil) {
		t.Fatal("empty evaluation incorrectly remained active")
	}
	breaker.mu.Lock()
	defer breaker.mu.Unlock()
	state := breaker.rules["snapshot"]
	if state.phase != http3RuleBreakerClosed || state.evaluationInFlight != 0 || len(state.evaluationBlackholes) != 0 {
		t.Fatalf("empty evaluation was not released: phase=%d inFlight=%d scopes=%d", state.phase, state.evaluationInFlight, len(state.evaluationBlackholes))
	}
}

func h3BlackholeSnapshotBreaker() (*http3RuleBreaker, http3UDPBlackholeScope, http3UDPBlackholeScope) {
	breaker := newHTTP3RuleBreaker(time.Now)
	first := http3UDPBlackholeScope{key: http3ConnectTransportKey{address: "first.example:443"}, slot: &http3ConnectTransportSlot{}, connectionID: 1}
	second := http3UDPBlackholeScope{key: http3ConnectTransportKey{address: "second.example:443"}, slot: &http3ConnectTransportSlot{}, connectionID: 2}
	breaker.register("snapshot", first.key)
	breaker.register("snapshot", second.key)
	return breaker, first, second
}

func h3BlackholeSnapshotAssertScopes(t *testing.T, got, want []http3UDPBlackholeScope) {
	t.Helper()
	if len(got) != len(want) {
		t.Fatalf("scope count = %d, want %d", len(got), len(want))
	}
	for index := range want {
		if got[index] != want[index] {
			t.Fatalf("scope %d = %+v, want %+v", index, got[index], want[index])
		}
	}
}

type h3BlackholeSnapshotStream struct {
	canceled atomic.Int64
	done     chan error
}

func h3BlackholeSnapshotBlockedStream(t *testing.T, manager *http3ConnectManager, event http3UDPBlackholeEvent) *h3BlackholeSnapshotStream {
	t.Helper()
	writer, peer := net.Pipe()
	stream := &h3BlackholeSnapshotStream{done: make(chan error, 1)}
	t.Cleanup(func() { _ = writer.Close(); _ = peer.Close() })
	manager.mu.Lock()
	for tunnel := range event.slot.tunnels {
		tunnel.fastFail = func() bool {
			stream.canceled.Add(1)
			_ = writer.Close()
			return true
		}
	}
	manager.mu.Unlock()
	go func() {
		_, err := writer.Write([]byte("pending application payload"))
		stream.done <- err
	}()
	return stream
}

func h3BlackholeSnapshotStreamReleased(t *testing.T, stream *h3BlackholeSnapshotStream) {
	t.Helper()
	select {
	case err := <-stream.done:
		if err == nil || stream.canceled.Load() != 1 {
			t.Fatalf("stream release: err=%v cancellation calls=%d", err, stream.canceled.Load())
		}
	case <-time.After(time.Second):
		t.Fatal("blocked stream was not fast-failed")
	}
}

func h3BlackholeSnapshotValidatorWaiting() bool {
	deadline := time.Now().Add(time.Second)
	buffer := make([]byte, 1<<20)
	for time.Now().Before(deadline) {
		stack := string(buffer[:runtime.Stack(buffer, true)])
		for _, goroutine := range strings.Split(stack, "\n\n") {
			if strings.Contains(goroutine, "http3BlackholeStillActive") && strings.Contains(goroutine, "retainActiveUDPBlackholeScopes") && strings.Contains(goroutine, "validateHTTP3UDPBlackholeFallback") {
				return true
			}
		}
		time.Sleep(time.Millisecond)
	}
	return false
}
