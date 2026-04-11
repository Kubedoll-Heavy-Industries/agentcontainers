package drift

import "fmt"

// Decision represents the enforcement action for a drift report.
type Decision string

const (
	// DecisionAutoApprove means the drift is trivial and can proceed without user input.
	DecisionAutoApprove Decision = "auto-approve"

	// DecisionNotify means the drift should be logged/displayed but not blocked.
	DecisionNotify Decision = "notify"

	// DecisionRequireApproval means a human must explicitly approve the update.
	DecisionRequireApproval Decision = "require-approval"

	// DecisionBlock means the update is blocked unconditionally.
	DecisionBlock Decision = "block"
)

// IsBlocking returns true if the decision prevents the update from proceeding.
func (d Decision) IsBlocking() bool {
	return d == DecisionBlock
}

// RequiresApproval returns true if the decision requires human approval.
func (d Decision) RequiresApproval() bool {
	return d == DecisionRequireApproval
}

// decisionRank returns a numeric rank for decision precedence.
// Higher rank = stricter decision. When multiple signals contribute
// different decisions, the strictest one wins.
func decisionRank(d Decision) int {
	switch d {
	case DecisionAutoApprove:
		return 0
	case DecisionNotify:
		return 1
	case DecisionRequireApproval:
		return 2
	case DecisionBlock:
		return 3
	default:
		return -1
	}
}

// ThresholdKey identifies a (severity, kind) pair for threshold lookup.
type ThresholdKey struct {
	Severity Severity
	Kind     Kind
}

// EnforcementThresholds maps (severity, kind) pairs to enforcement decisions.
// If a specific (severity, kind) pair is not found, a severity-only fallback
// is used. Callers can override individual signal types while relying on
// severity defaults for everything else.
type EnforcementThresholds struct {
	// Rules maps specific (severity, kind) pairs to decisions.
	Rules map[ThresholdKey]Decision

	// SeverityDefaults maps a severity level to its default decision.
	// Used when no specific (severity, kind) rule is found.
	SeverityDefaults map[Severity]Decision
}

// Lookup returns the decision for a given signal. It first checks for a
// specific (severity, kind) rule, then falls back to the severity default.
// If neither is found, it returns DecisionBlock (fail-closed).
func (t *EnforcementThresholds) Lookup(severity Severity, kind Kind) Decision {
	if d, ok := t.Rules[ThresholdKey{Severity: severity, Kind: kind}]; ok {
		return d
	}
	if d, ok := t.SeverityDefaults[severity]; ok {
		return d
	}
	return DecisionBlock // fail-closed
}

// DefaultEnforcementThresholds returns sensible defaults:
//   - Critical severity -> Block
//   - High + capability-added (dangerous) -> RequireApproval
//   - High (other) -> RequireApproval
//   - Medium -> Notify
//   - Low -> AutoApprove
func DefaultEnforcementThresholds() *EnforcementThresholds {
	return &EnforcementThresholds{
		Rules: map[ThresholdKey]Decision{
			// Dangerous capability additions are always blocked.
			{Severity: SeverityCritical, Kind: KindCapabilityAdded}: DecisionBlock,
		},
		SeverityDefaults: map[Severity]Decision{
			SeverityCritical: DecisionBlock,
			SeverityHigh:     DecisionRequireApproval,
			SeverityMedium:   DecisionNotify,
			SeverityLow:      DecisionAutoApprove,
		},
	}
}

// EnforcementResult pairs a Decision with the signals that contributed to it.
type EnforcementResult struct {
	// Decision is the overall enforcement action (strictest across all signals).
	Decision Decision

	// SignalDecisions maps each signal index to its individual decision.
	SignalDecisions []SignalDecision
}

// SignalDecision pairs a DriftSignal with the decision applied to it.
type SignalDecision struct {
	Signal   DriftSignal
	Decision Decision
}

// EnforceThresholds evaluates a drift Report against the given thresholds
// and returns the strictest decision across all signals. If no signals are
// present, it returns DecisionAutoApprove.
func EnforceThresholds(report *Report, thresholds *EnforcementThresholds) *EnforcementResult {
	if len(report.Signals) == 0 {
		return &EnforcementResult{
			Decision: DecisionAutoApprove,
		}
	}

	overall := DecisionAutoApprove
	decisions := make([]SignalDecision, len(report.Signals))

	for i, sig := range report.Signals {
		d := thresholds.Lookup(sig.Severity, sig.Kind)
		decisions[i] = SignalDecision{
			Signal:   sig,
			Decision: d,
		}
		if decisionRank(d) > decisionRank(overall) {
			overall = d
		}
	}

	return &EnforcementResult{
		Decision:        overall,
		SignalDecisions: decisions,
	}
}

// FormatEnforcementResult produces a human-readable summary of the enforcement result.
func FormatEnforcementResult(result *EnforcementResult) string {
	switch result.Decision {
	case DecisionAutoApprove:
		return "PASS: all signals auto-approved"
	case DecisionNotify:
		return "NOTICE: drift detected but within acceptable thresholds"
	case DecisionRequireApproval:
		count := 0
		for _, sd := range result.SignalDecisions {
			if sd.Decision.RequiresApproval() {
				count++
			}
		}
		return fmt.Sprintf("APPROVAL REQUIRED: %d signal(s) require human review", count)
	case DecisionBlock:
		count := 0
		for _, sd := range result.SignalDecisions {
			if sd.Decision.IsBlocking() {
				count++
			}
		}
		return fmt.Sprintf("BLOCKED: %d signal(s) exceed acceptable drift thresholds", count)
	default:
		return fmt.Sprintf("UNKNOWN DECISION: %s", result.Decision)
	}
}
