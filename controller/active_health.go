package controller

import (
	"context"
	"errors"
	"fmt"
	"math/rand/v2"
	"net"
	"net/http"
	"net/url"
	"sync"
	"time"

	"moto/config"
)

var ErrActiveHealthUnhealthy = errors.New("target marked unhealthy by active health checks")

const (
	activeHealthMaxConcurrentProbes = 32
	activeHealthJitterPercent       = 10
	activeHealthMaxResponseHeaders  = 32 << 10
	activeHealthRecoveryConfirmCap  = 1500 * time.Millisecond
)

// The slot pool is process-wide rather than per server generation. This keeps
// simultaneous reload generations and multiple embedded servers from
// multiplying the number of background network operations.
var activeHealthProbeSlots = make(chan struct{}, activeHealthMaxConcurrentProbes)

type activeHealthKey struct {
	rule    *config.Rule
	address string
}

type activeHealthState struct {
	unhealthy            bool
	consecutiveFailures  int
	consecutiveSuccesses int
	requiredSuccesses    int
	nextProbeAt          time.Time
	probeInFlight        bool
	lastProbeSuccess     time.Time
	lastRecovery         time.Time
}

type activeHealthJob struct {
	key               activeHealthKey
	target            string
	check             config.HealthCheckConfig
	proxyProtocol     string
	failureConclusive bool
}

type activeHealthProbeFunc func(context.Context, string, config.HealthCheckConfig, string) error
type activeHealthDelayFunc func(time.Duration) time.Duration

// activeHealthManager owns the active state for one routing generation. It is
// intentionally independent from passive route health: a later integration can
// exclude actively unhealthy targets without letting background probes distort
// EWMA latency or half-open ownership.
type activeHealthManager struct {
	mu     sync.RWMutex
	states map[activeHealthKey]*activeHealthState

	lifecycleMu sync.Mutex
	started     bool
	cancel      context.CancelFunc
	wg          sync.WaitGroup

	probe        activeHealthProbeFunc
	initialDelay activeHealthDelayFunc
	nextDelay    activeHealthDelayFunc
	now          func() time.Time
	waitDelay    func(context.Context, time.Duration) bool
}

func newActiveHealthManager() *activeHealthManager {
	return &activeHealthManager{
		states:       make(map[activeHealthKey]*activeHealthState),
		probe:        probeActiveHealthTarget,
		initialDelay: activeHealthInitialDelay,
		nextDelay:    activeHealthIntervalDelay,
		now:          time.Now,
		waitDelay:    waitActiveHealthDelay,
	}
}

// start launches at most one checker for each rule/target address. Configuration
// validation happens before server construction, so this lifecycle method only
// ignores nil or disabled entries defensively.
func (manager *activeHealthManager) start(parent context.Context, rules []*config.Rule) {
	if manager == nil {
		return
	}
	if parent == nil {
		parent = context.Background()
	}

	manager.lifecycleMu.Lock()
	if manager.started {
		manager.lifecycleMu.Unlock()
		return
	}
	manager.started = true
	ctx, cancel := context.WithCancel(parent)
	manager.cancel = cancel

	jobs := make([]activeHealthJob, 0)
	seen := make(map[activeHealthKey]int)
	for _, rule := range rules {
		if rule == nil || rule.HealthCheck == nil {
			continue
		}
		for _, target := range rule.Targets {
			if target == nil || target.Address == "" {
				continue
			}
			key := activeHealthKey{rule: rule, address: target.Address}
			if jobIndex, duplicate := seen[key]; duplicate {
				// Duplicate addresses share one route-health key. A TCP failure
				// remains inconclusive when any duplicate can still use HTTP/3.
				if !activeHealthFailureConclusive(rule, target) {
					jobs[jobIndex].failureConclusive = false
				}
				continue
			}
			seen[key] = len(jobs)
			proxyProtocol := ""
			if rule.ProxyProtocol != nil {
				proxyProtocol = rule.ProxyProtocol.Send
			}
			jobs = append(jobs, activeHealthJob{
				key:               key,
				target:            target.Address,
				check:             *rule.HealthCheck,
				proxyProtocol:     proxyProtocol,
				failureConclusive: activeHealthFailureConclusive(rule, target),
			})
		}
	}
	manager.mu.Lock()
	for _, job := range jobs {
		if manager.states[job.key] == nil {
			manager.states[job.key] = &activeHealthState{}
		}
		state := manager.states[job.key]
		state.requiredSuccesses = job.check.SuccessThreshold
		// Reloads inherit confirmation evidence, but scheduling and probe
		// capacity belong exclusively to the checker in this generation.
		state.nextProbeAt = time.Time{}
		state.probeInFlight = false
	}
	manager.mu.Unlock()
	manager.wg.Add(len(jobs))
	for _, job := range jobs {
		go manager.runChecker(ctx, job)
	}
	manager.lifecycleMu.Unlock()
}

// stop cancels timer waits, semaphore waits, dials, and HTTP requests, then
// waits until every checker has exited. It is safe to call repeatedly.
func (manager *activeHealthManager) stop() {
	if manager == nil {
		return
	}
	manager.lifecycleMu.Lock()
	cancel := manager.cancel
	manager.lifecycleMu.Unlock()
	if cancel != nil {
		cancel()
	}
	manager.wg.Wait()
}

// unhealthy reports only a threshold-confirmed active failure. Missing,
// disabled, and not-yet-checked targets remain usable, preserving legacy
// passive routing during startup and when active checking is omitted.
func (manager *activeHealthManager) unhealthy(rule *config.Rule, address string) bool {
	if manager == nil || rule == nil || address == "" {
		return false
	}
	manager.mu.RLock()
	state := manager.states[activeHealthKey{rule: rule, address: address}]
	unhealthy := state != nil && state.unhealthy
	manager.mu.RUnlock()
	return unhealthy
}

func (manager *activeHealthManager) runChecker(ctx context.Context, job activeHealthJob) {
	defer manager.wg.Done()
	defer func() {
		manager.mu.Lock()
		if state := manager.states[job.key]; state != nil {
			state.nextProbeAt = time.Time{}
			state.probeInFlight = false
		}
		manager.mu.Unlock()
	}()
	interval := time.Duration(job.check.Interval) * time.Millisecond
	delay := manager.initialDelay(interval)
	for {
		manager.mu.Lock()
		manager.states[job.key].nextProbeAt = manager.now().Add(max(delay, 0))
		manager.mu.Unlock()
		if !manager.waitDelay(ctx, delay) {
			return
		}
		if !manager.runProbe(ctx, job) {
			return
		}
		delay = manager.nextProbeDelay(job, interval)
	}
}

// Only the second consecutive recovery confirmation gets a shorter base
// interval. Healthy probes, failures, HTTP checks, and further confirmations
// keep the configured cadence. The usual jitter still applies to either base.
func (manager *activeHealthManager) nextProbeDelay(job activeHealthJob, interval time.Duration) time.Duration {
	manager.mu.RLock()
	state := manager.states[job.key]
	confirmRecovery := job.check.Type == config.HealthCheckTCP && state != nil &&
		state.unhealthy && state.consecutiveSuccesses == 1
	manager.mu.RUnlock()
	if confirmRecovery {
		interval = min(interval, activeHealthRecoveryConfirmCap)
	}
	return manager.nextDelay(interval)
}

func waitActiveHealthDelay(ctx context.Context, delay time.Duration) bool {
	if delay < 0 {
		delay = 0
	}
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-timer.C:
		return true
	}
}

func (manager *activeHealthManager) runProbe(ctx context.Context, job activeHealthJob) bool {
	if ctx.Err() != nil {
		return false
	}
	select {
	case activeHealthProbeSlots <- struct{}{}:
	case <-ctx.Done():
		return false
	}
	if ctx.Err() != nil {
		<-activeHealthProbeSlots
		return false
	}
	manager.mu.Lock()
	state := manager.states[job.key]
	if state == nil {
		state = &activeHealthState{requiredSuccesses: job.check.SuccessThreshold}
		manager.states[job.key] = state
	}
	state.nextProbeAt = time.Time{}
	state.probeInFlight = true
	manager.mu.Unlock()

	timeout := time.Duration(job.check.Timeout) * time.Millisecond
	probeCtx, cancel := context.WithTimeout(ctx, timeout)
	err := manager.probe(probeCtx, job.target, job.check, job.proxyProtocol)
	parentCanceled := ctx.Err() != nil
	cancel()
	manager.mu.Lock()
	defer manager.mu.Unlock()
	state.probeInFlight = false
	<-activeHealthProbeSlots
	if parentCanceled {
		return false
	}
	// A TCP probe can prove the H2 leg is reachable, but its failure cannot
	// prove an H3-capable proxy target is down: H3 uses UDP and may remain fully
	// usable during a TCP outage. Keep the target eligible and let real H3/H2
	// CONNECT attempts update passive route health instead.
	if err == nil || job.failureConclusive {
		manager.observeLocked(state, job.check, err == nil)
	} else {
		// An inconclusive TCP failure cannot mark an H3 target unhealthy, but
		// it also cannot count toward consecutive successful confirmations.
		state.consecutiveSuccesses = 0
	}
	return true
}

func activeHealthFailureConclusive(rule *config.Rule, target *config.Target) bool {
	if rule == nil || target == nil || rule.HealthCheck == nil ||
		rule.HealthCheck.Type != config.HealthCheckTCP || target.ConnectProxy == nil {
		return true
	}
	for _, protocol := range target.ConnectProxy.Protocols {
		if protocol == config.ConnectProxyH3 {
			return false
		}
	}
	return true
}

func (manager *activeHealthManager) observe(key activeHealthKey, check config.HealthCheckConfig, success bool) {
	manager.mu.Lock()
	defer manager.mu.Unlock()
	state := manager.states[key]
	if state == nil {
		state = &activeHealthState{}
		manager.states[key] = state
	}
	manager.observeLocked(state, check, success)
}

func (manager *activeHealthManager) observeLocked(state *activeHealthState, check config.HealthCheckConfig, success bool) {
	state.requiredSuccesses = check.SuccessThreshold
	if success {
		now := manager.now()
		state.lastProbeSuccess = now
		state.consecutiveFailures = 0
		if !state.unhealthy {
			state.consecutiveSuccesses = 0
			return
		}
		state.consecutiveSuccesses++
		if state.consecutiveSuccesses >= check.SuccessThreshold {
			state.unhealthy = false
			state.consecutiveSuccesses = 0
			state.lastRecovery = now
		}
		return
	}

	state.consecutiveSuccesses = 0
	if state.unhealthy {
		return
	}
	state.consecutiveFailures++
	if state.consecutiveFailures >= check.FailureThreshold {
		state.unhealthy = true
		state.consecutiveFailures = 0
	}
}

func activeHealthInitialDelay(interval time.Duration) time.Duration {
	maximum := interval * activeHealthJitterPercent / 100
	return activeHealthRandomDuration(maximum)
}

func activeHealthIntervalDelay(interval time.Duration) time.Duration {
	spread := interval * activeHealthJitterPercent / 100
	if spread <= 0 {
		return interval
	}
	return interval - spread + activeHealthRandomDuration(2*spread)
}

func activeHealthRandomDuration(maximum time.Duration) time.Duration {
	if maximum <= 0 {
		return 0
	}
	return time.Duration(rand.Int64N(int64(maximum) + 1))
}

func probeActiveHealthTarget(ctx context.Context, address string, check config.HealthCheckConfig, proxyProtocol string) error {
	switch check.Type {
	case config.HealthCheckTCP:
		connection, err := dialActiveHealthTarget(ctx, "tcp", address, proxyProtocol)
		if err != nil {
			return err
		}
		_ = connection.Close()
		return nil
	case config.HealthCheckHTTP:
		return probeActiveHealthHTTP(ctx, address, check, proxyProtocol)
	default:
		return fmt.Errorf("unsupported active health check type %q", check.Type)
	}
}

func dialActiveHealthTarget(ctx context.Context, network, address, proxyProtocol string) (net.Conn, error) {
	connection, err := (&net.Dialer{}).DialContext(ctx, network, address)
	if err != nil {
		return nil, err
	}
	configureTCP(connection)
	if proxyProtocol == "" {
		return connection, nil
	}
	if err := writeActiveHealthProxyProtocolContext(ctx, connection, proxyProtocol); err != nil {
		_ = connection.Close()
		return nil, err
	}
	return connection, nil
}

func writeActiveHealthProxyProtocolContext(ctx context.Context, connection net.Conn, version string) error {
	return writeProxyProtocolWithContext(ctx, connection, "active health", func() error {
		return writeActiveHealthProxyProtocol(connection, version)
	})
}

func writeActiveHealthProxyProtocol(connection net.Conn, version string) error {
	if version == "" {
		return nil
	}
	if connection == nil {
		return errors.New("write active health PROXY protocol header: nil connection")
	}

	header := proxyProtocolHeader{Command: proxyProtocolCommandLocal}
	switch version {
	case config.ProxyProtocolV1:
		source, err := addrPortFromNetAddr(connection.LocalAddr())
		if err != nil {
			return fmt.Errorf("active health PROXY protocol source: %w", err)
		}
		destination, err := addrPortFromNetAddr(connection.RemoteAddr())
		if err != nil {
			return fmt.Errorf("active health PROXY protocol destination: %w", err)
		}
		header.Version = proxyProtocolVersion1
		header.Command = proxyProtocolCommandProxy
		header.Source = source
		header.Destination = destination
	case config.ProxyProtocolV2:
		header.Version = proxyProtocolVersion2
	default:
		return fmt.Errorf("unsupported active health PROXY protocol version %q", version)
	}
	if err := writeProxyProtocolHeader(connection, header); err != nil {
		return fmt.Errorf("write active health PROXY protocol header: %w", err)
	}
	return nil
}

func probeActiveHealthHTTP(ctx context.Context, address string, check config.HealthCheckConfig, proxyProtocol string) error {
	requestTarget, err := url.ParseRequestURI(check.Path)
	if err != nil {
		return fmt.Errorf("parse health check path: %w", err)
	}
	endpoint := &url.URL{
		Scheme:   "http",
		Host:     address,
		Path:     requestTarget.Path,
		RawPath:  requestTarget.RawPath,
		RawQuery: requestTarget.RawQuery,
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint.String(), nil)
	if err != nil {
		return fmt.Errorf("create health check request: %w", err)
	}
	transport := &http.Transport{
		Proxy: nil,
		DialContext: func(dialCtx context.Context, network, target string) (net.Conn, error) {
			return dialActiveHealthTarget(dialCtx, network, target, proxyProtocol)
		},
		DisableKeepAlives:      true,
		DisableCompression:     true,
		ForceAttemptHTTP2:      false,
		MaxResponseHeaderBytes: activeHealthMaxResponseHeaders,
	}
	defer transport.CloseIdleConnections()
	client := &http.Client{
		Transport: transport,
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	response, err := client.Do(request)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	if response.StatusCode < check.StatusMin || response.StatusCode > check.StatusMax {
		return fmt.Errorf("unexpected HTTP status %d (want %d-%d)", response.StatusCode, check.StatusMin, check.StatusMax)
	}
	return nil
}
