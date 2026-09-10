package controller

import (
	"context"
	"moto/utils"
	"strconv"
	"strings"
	"time"

	"go.uber.org/zap"
)

// The latest completed probation survives cooldown and the next probation. All
// classifications below are local enums; peer text, credentials, destinations,
// and connection IDs must never become metric labels.
type http3RuleRecoveryResult struct {
	result         string
	reason         string
	completedAt    time.Time
	elapsed        time.Duration
	evidence       bool
	payloadBytes   uint64
	packetsSent    uint64
	healthySamples int
}

func http3RecoveryClassification(reason string, aborted bool) (string, string) {
	if aborted {
		switch reason {
		case "canceled", "capacity", "protocol_unavailable", "target_cooldown", "no_network":
			return "aborted", reason
		default:
			return "aborted", "unknown"
		}
	}
	switch reason {
	case "recovered":
		return "recovered", reason
	case "probe_closed", "observation_timeout":
		return "insufficient_evidence", reason
	case "insufficient_evidence":
		return "insufficient_evidence", "unknown"
	case "transport_degraded":
		return "transport_degraded", reason
	case "missing_transport_evidence":
		return "setup_failed", reason
	default:
		return "setup_failed", "setup_failed"
	}
}

func (state *http3RuleBreakerState) finishRecoveryLocked(at time.Time, reason string, aborted bool) http3RuleRecoveryResult {
	result, detail := http3RecoveryClassification(reason, aborted)
	probe := state.probation
	last := http3RuleRecoveryResult{
		result: result, reason: detail, completedAt: at, evidence: probe.established,
		payloadBytes: probe.payloadBytes, packetsSent: probe.packetsSent, healthySamples: probe.healthySamples,
	}
	if probe.established {
		last.elapsed = max(time.Duration(0), at.Sub(probe.establishedAt))
	}
	state.lastRecovery = last
	return last
}

func (result http3RuleRecoveryResult) requirementsMet() [3]bool {
	if result.result == "recovered" {
		return [3]bool{true, true, true}
	}
	return [3]bool{
		result.elapsed >= http3RuleProbationMinDuration,
		result.payloadBytes >= http3RuleProbationMinPayload || result.packetsSent >= http3RuleProbationMinPackets,
		result.healthySamples >= http3RuleProbationHealthyCount,
	}
}

func (result http3RuleRecoveryResult) fields() []zap.Field {
	fields := []zap.Field{
		zap.String("recoveryResult", result.result), zap.String("recoveryReason", result.reason),
		zap.Bool("recoveryEvidenceAvailable", result.evidence),
		zap.Float64("minObservedSeconds", http3RuleProbationMinDuration.Seconds()),
		zap.Float64("maxObservedSeconds", http3RuleProbationMaxDuration.Seconds()),
		zap.Uint64("minPayloadBytes", http3RuleProbationMinPayload),
		zap.Uint64("minPacketsSent", http3RuleProbationMinPackets),
		zap.Int("minHealthySamples", http3RuleProbationHealthyCount),
	}
	if !result.evidence {
		return fields
	}
	missing := make([]string, 0, 3)
	for index, met := range result.requirementsMet() {
		if !met {
			missing = append(missing, http3RecoveryRequirements[index])
		}
	}
	return append(fields,
		zap.Float64("observedSeconds", result.elapsed.Seconds()),
		zap.Uint64("payloadBytes", result.payloadBytes), zap.Uint64("packetsSent", result.packetsSent),
		zap.Int("healthySamples", result.healthySamples), zap.Strings("requirementsMissing", missing))
}

var http3RecoveryRequirements = [...]string{"duration", "data", "healthy_samples"}

// Capture the final counters before Close can evict the physical connection.
// This is one read per completed probation, not a new sampling loop. Never hold
// the rule-breaker and transport-manager locks together.
func (manager *connectProxyManager) snapshotHTTP3RuleProbation(rule string, token uint64) *http3RuleSampleEvent {
	if manager == nil || manager.h3RuleBreaker == nil || manager.h3 == nil {
		return nil
	}
	breaker := manager.h3RuleBreaker
	breaker.mu.Lock()
	state := breaker.rules[rule]
	if state == nil || state.phase != http3RuleBreakerProbation || state.probation.token != token || !state.probation.established {
		breaker.mu.Unlock()
		return nil
	}
	probe := state.probation
	breaker.mu.Unlock()
	manager.h3.mu.Lock()
	defer manager.h3.mu.Unlock()
	for _, slot := range manager.h3.transports[probe.key] {
		if slot != nil && slot.generationID == probe.generationID && slot.connection != nil {
			return &http3RuleSampleEvent{
				key: probe.key, generationID: probe.generationID, at: breaker.now(),
				stats:         slot.connection.ConnectionStats(),
				payloadBytes:  saturatingAdd(slot.payloadRead.Load(), slot.payloadWritten.Load()),
				connectionErr: context.Cause(slot.connection.Context()),
				decision:      slot.lastDecision,
			}
		}
	}
	return nil
}

func (probe *http3RuleProbationState) updateEvidence(event http3RuleSampleEvent) {
	if event.payloadBytes >= probe.initialPayload {
		probe.payloadBytes = max(probe.payloadBytes, event.payloadBytes-probe.initialPayload)
	}
	if event.stats.PacketsSent >= probe.initialStats.PacketsSent {
		probe.packetsSent = max(probe.packetsSent, event.stats.PacketsSent-probe.initialStats.PacketsSent)
	}
}

func logHTTP3RecoveryResult(message, rule, legacyReason string, delay time.Duration, result http3RuleRecoveryResult) {
	fields := append([]zap.Field{zap.String("ruleName", rule)}, result.fields()...)
	if legacyReason != "" {
		if _, detail := http3RecoveryClassification(legacyReason, result.result == "aborted"); detail != legacyReason && legacyReason != "insufficient_evidence" && !connectProxyAttemptOutcomeValid(legacyReason) {
			legacyReason = "unknown"
		}
		fields = append(fields, zap.String("reason", legacyReason))
	}
	if delay > 0 {
		fields = append(fields, zap.Duration("retryAfter", delay))
	}
	if result.result == "recovered" || result.result == "aborted" {
		utils.Logger.Info(message, fields...)
	} else {
		utils.Logger.Warn(message, fields...)
	}
}

func writeHTTP3RecoveryGauges(output *strings.Builder, rules []http3RuleBreakerGauge) {
	const prefix = "moto_connect_proxy_h3_rule_recovery_"
	for _, metric := range []struct {
		suffix string
		help   string
		value  float64
	}{
		{"min_duration_seconds", "Minimum observation duration required for HTTP/3 recovery.", http3RuleProbationMinDuration.Seconds()},
		{"max_duration_seconds", "Maximum observation duration before insufficient HTTP/3 recovery evidence returns to cooldown.", http3RuleProbationMaxDuration.Seconds()},
		{"min_payload_bytes", "Payload alternative of the HTTP/3 recovery data requirement; payload OR packets must qualify.", float64(http3RuleProbationMinPayload)},
		{"min_packets_sent", "Packet alternative of the HTTP/3 recovery data requirement; payload OR packets must qualify.", float64(http3RuleProbationMinPackets)},
		{"min_healthy_samples", "Consecutive healthy samples required for HTTP/3 recovery.", http3RuleProbationHealthyCount},
	} {
		writeMetricHeader(output, prefix+metric.suffix, metric.help, "gauge")
		for _, rule := range rules {
			writeMetricSample(output, prefix+metric.suffix, []prometheusLabel{{"rule", rule.rule}}, strconv.FormatFloat(metric.value, 'g', -1, 64))
		}
	}
	for _, metric := range []struct{ suffix, help string }{
		{"last_result", "Latest completed HTTP/3 recovery outcome; absent until one completes. Fixed local classifications only."},
		{"last_timestamp_seconds", "Unix timestamp of the latest completed HTTP/3 recovery attempt."},
		{"last_elapsed_seconds", "Observed data-plane duration at completion; absent when no transport evidence was available."},
		{"last_payload_bytes", "Latest observed payload bytes at recovery completion; absent without transport evidence."},
		{"last_packets_sent", "Latest observed QUIC packets sent at recovery completion; absent without transport evidence."},
		{"last_healthy_samples", "Consecutive healthy samples at recovery completion; absent without transport evidence."},
		{"last_requirement_met", "Whether a recovery evidence requirement was met; data means payload OR packets. Absent without transport evidence."},
	} {
		writeMetricHeader(output, prefix+metric.suffix, metric.help, "gauge")
		for _, rule := range rules {
			last := rule.lastRecovery
			if last.result == "" {
				continue
			}
			labels := []prometheusLabel{{"rule", rule.rule}}
			switch metric.suffix {
			case "last_result":
				writeMetricSample(output, prefix+metric.suffix, append(labels, prometheusLabel{"result", last.result}, prometheusLabel{"reason", last.reason}), "1")
			case "last_timestamp_seconds":
				writeMetricSample(output, prefix+metric.suffix, labels, strconv.FormatFloat(float64(last.completedAt.UnixNano())/1e9, 'f', -1, 64))
			default:
				if !last.evidence {
					continue
				}
				switch metric.suffix {
				case "last_elapsed_seconds":
					writeMetricSample(output, prefix+metric.suffix, labels, strconv.FormatFloat(last.elapsed.Seconds(), 'g', -1, 64))
				case "last_payload_bytes":
					writeMetricSample(output, prefix+metric.suffix, labels, strconv.FormatUint(last.payloadBytes, 10))
				case "last_packets_sent":
					writeMetricSample(output, prefix+metric.suffix, labels, strconv.FormatUint(last.packetsSent, 10))
				case "last_healthy_samples":
					writeMetricSample(output, prefix+metric.suffix, labels, strconv.Itoa(last.healthySamples))
				case "last_requirement_met":
					for index, met := range last.requirementsMet() {
						writeMetricSample(output, prefix+metric.suffix, append(labels, prometheusLabel{"requirement", http3RecoveryRequirements[index]}), boolMetric(met))
					}
				}
			}
		}
	}
}
