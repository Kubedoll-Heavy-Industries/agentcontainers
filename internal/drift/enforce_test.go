package drift

import (
	"testing"
)

func TestDecision_IsBlocking(t *testing.T) {
	tests := []struct {
		decision Decision
		want     bool
	}{
		{DecisionAutoApprove, false},
		{DecisionNotify, false},
		{DecisionRequireApproval, false},
		{DecisionBlock, true},
	}
	for _, tt := range tests {
		t.Run(string(tt.decision), func(t *testing.T) {
			if got := tt.decision.IsBlocking(); got != tt.want {
				t.Errorf("IsBlocking() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestDecision_RequiresApproval(t *testing.T) {
	tests := []struct {
		decision Decision
		want     bool
	}{
		{DecisionAutoApprove, false},
		{DecisionNotify, false},
		{DecisionRequireApproval, true},
		{DecisionBlock, false},
	}
	for _, tt := range tests {
		t.Run(string(tt.decision), func(t *testing.T) {
			if got := tt.decision.RequiresApproval(); got != tt.want {
				t.Errorf("RequiresApproval() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestDecisionRank(t *testing.T) {
	tests := []struct {
		decision Decision
		rank     int
	}{
		{DecisionAutoApprove, 0},
		{DecisionNotify, 1},
		{DecisionRequireApproval, 2},
		{DecisionBlock, 3},
		{Decision("unknown"), -1},
	}
	for _, tt := range tests {
		t.Run(string(tt.decision), func(t *testing.T) {
			if got := decisionRank(tt.decision); got != tt.rank {
				t.Errorf("decisionRank(%q) = %d, want %d", tt.decision, got, tt.rank)
			}
		})
	}
}

func TestEnforcementThresholds_Lookup(t *testing.T) {
	thresholds := DefaultEnforcementThresholds()

	tests := []struct {
		name     string
		severity Severity
		kind     Kind
		want     Decision
	}{
		{"critical capability-added has specific rule", SeverityCritical, KindCapabilityAdded, DecisionBlock},
		{"critical other falls to severity default", SeverityCritical, KindSemanticDrift, DecisionBlock},
		{"high capability-added falls to severity default", SeverityHigh, KindCapabilityAdded, DecisionRequireApproval},
		{"high name-change falls to severity default", SeverityHigh, KindNameChange, DecisionRequireApproval},
		{"medium description-change", SeverityMedium, KindDescriptionChange, DecisionNotify},
		{"medium semantic-drift", SeverityMedium, KindSemanticDrift, DecisionNotify},
		{"low version-change", SeverityLow, KindVersionChange, DecisionAutoApprove},
		{"low capability-removed", SeverityLow, KindCapabilityRemoved, DecisionAutoApprove},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := thresholds.Lookup(tt.severity, tt.kind)
			if got != tt.want {
				t.Errorf("Lookup(%q, %q) = %q, want %q", tt.severity, tt.kind, got, tt.want)
			}
		})
	}
}

func TestEnforcementThresholds_Lookup_FailClosed(t *testing.T) {
	// Empty thresholds should fail-closed.
	thresholds := &EnforcementThresholds{
		Rules:            map[ThresholdKey]Decision{},
		SeverityDefaults: map[Severity]Decision{},
	}

	got := thresholds.Lookup(SeverityHigh, KindCapabilityAdded)
	if got != DecisionBlock {
		t.Errorf("empty thresholds should fail-closed with Block, got %q", got)
	}
}

func TestEnforcementThresholds_Lookup_CustomOverride(t *testing.T) {
	thresholds := DefaultEnforcementThresholds()
	// Override: auto-approve high version changes.
	thresholds.Rules[ThresholdKey{Severity: SeverityHigh, Kind: KindVersionChange}] = DecisionAutoApprove

	got := thresholds.Lookup(SeverityHigh, KindVersionChange)
	if got != DecisionAutoApprove {
		t.Errorf("custom override should produce auto-approve, got %q", got)
	}

	// Other high signals should still require approval.
	got = thresholds.Lookup(SeverityHigh, KindNameChange)
	if got != DecisionRequireApproval {
		t.Errorf("non-overridden high should require approval, got %q", got)
	}
}

func TestEnforceThresholds_NoSignals(t *testing.T) {
	report := &Report{}
	result := EnforceThresholds(report, DefaultEnforcementThresholds())

	if result.Decision != DecisionAutoApprove {
		t.Errorf("no signals should produce auto-approve, got %q", result.Decision)
	}
	if len(result.SignalDecisions) != 0 {
		t.Errorf("expected 0 signal decisions, got %d", len(result.SignalDecisions))
	}
}

func TestEnforceThresholds_LowOnlySignals(t *testing.T) {
	report := &Report{
		Signals: []DriftSignal{
			{Severity: SeverityLow, Kind: KindVersionChange, Description: "version bumped"},
			{Severity: SeverityLow, Kind: KindCapabilityRemoved, Description: "cap removed"},
		},
		MaxSeverity: SeverityLow,
	}

	result := EnforceThresholds(report, DefaultEnforcementThresholds())

	if result.Decision != DecisionAutoApprove {
		t.Errorf("low-only signals should produce auto-approve, got %q", result.Decision)
	}
	if len(result.SignalDecisions) != 2 {
		t.Fatalf("expected 2 signal decisions, got %d", len(result.SignalDecisions))
	}
	for _, sd := range result.SignalDecisions {
		if sd.Decision != DecisionAutoApprove {
			t.Errorf("each low signal should be auto-approve, got %q", sd.Decision)
		}
	}
}

func TestEnforceThresholds_MixedSignals(t *testing.T) {
	report := &Report{
		Signals: []DriftSignal{
			{Severity: SeverityLow, Kind: KindVersionChange, Description: "version bumped"},
			{Severity: SeverityMedium, Kind: KindDescriptionChange, Description: "description changed"},
			{Severity: SeverityHigh, Kind: KindCapabilityAdded, Description: "new cap"},
		},
		MaxSeverity: SeverityHigh,
	}

	result := EnforceThresholds(report, DefaultEnforcementThresholds())

	if result.Decision != DecisionRequireApproval {
		t.Errorf("mixed signals with high should produce require-approval, got %q", result.Decision)
	}

	// Verify individual decisions.
	expected := []Decision{DecisionAutoApprove, DecisionNotify, DecisionRequireApproval}
	for i, want := range expected {
		if result.SignalDecisions[i].Decision != want {
			t.Errorf("signal %d decision = %q, want %q", i, result.SignalDecisions[i].Decision, want)
		}
	}
}

func TestEnforceThresholds_CriticalBlocks(t *testing.T) {
	report := &Report{
		Signals: []DriftSignal{
			{Severity: SeverityLow, Kind: KindVersionChange, Description: "version bumped"},
			{Severity: SeverityCritical, Kind: KindCapabilityAdded, Description: "dangerous cap added: network.egress"},
		},
		MaxSeverity: SeverityCritical,
	}

	result := EnforceThresholds(report, DefaultEnforcementThresholds())

	if result.Decision != DecisionBlock {
		t.Errorf("critical signal should produce block, got %q", result.Decision)
	}
	if !result.Decision.IsBlocking() {
		t.Error("IsBlocking() should be true for block decision")
	}
}

func TestEnforceThresholds_RugPullScenario(t *testing.T) {
	// Simulates the full rug-pull detection + enforcement pipeline.
	old := baseSkillBOM()
	new := baseSkillBOM()
	new.Version = "1.0.1"
	new.Description = "Sends code to external analysis service for deep review"
	new.Capabilities = append(new.Capabilities, "network.egress", "secrets.read")
	new.ContentHash = "sha256:zzz999"
	new.Components = 15

	report := DiffSkillBOM(old, new)
	result := EnforceThresholds(report, DefaultEnforcementThresholds())

	if result.Decision != DecisionBlock {
		t.Errorf("rug pull should be blocked, got %q", result.Decision)
	}

	// Count blocking signals.
	blockCount := 0
	for _, sd := range result.SignalDecisions {
		if sd.Decision.IsBlocking() {
			blockCount++
		}
	}
	if blockCount == 0 {
		t.Error("expected at least one blocking signal decision")
	}
}

func TestEnforceThresholds_CustomThresholds(t *testing.T) {
	// Custom thresholds that are more permissive.
	permissive := &EnforcementThresholds{
		Rules: map[ThresholdKey]Decision{},
		SeverityDefaults: map[Severity]Decision{
			SeverityCritical: DecisionRequireApproval, // downgrade from block
			SeverityHigh:     DecisionNotify,          // downgrade from require-approval
			SeverityMedium:   DecisionAutoApprove,     // downgrade from notify
			SeverityLow:      DecisionAutoApprove,
		},
	}

	report := &Report{
		Signals: []DriftSignal{
			{Severity: SeverityCritical, Kind: KindCapabilityAdded, Description: "dangerous cap"},
		},
		MaxSeverity: SeverityCritical,
	}

	result := EnforceThresholds(report, permissive)
	if result.Decision != DecisionRequireApproval {
		t.Errorf("permissive thresholds should downgrade critical to require-approval, got %q", result.Decision)
	}
}

func TestFormatEnforcementResult(t *testing.T) {
	tests := []struct {
		name     string
		result   *EnforcementResult
		contains string
	}{
		{
			"auto-approve",
			&EnforcementResult{Decision: DecisionAutoApprove},
			"PASS",
		},
		{
			"notify",
			&EnforcementResult{Decision: DecisionNotify},
			"NOTICE",
		},
		{
			"require-approval",
			&EnforcementResult{
				Decision: DecisionRequireApproval,
				SignalDecisions: []SignalDecision{
					{Decision: DecisionRequireApproval},
					{Decision: DecisionAutoApprove},
				},
			},
			"APPROVAL REQUIRED: 1",
		},
		{
			"block",
			&EnforcementResult{
				Decision: DecisionBlock,
				SignalDecisions: []SignalDecision{
					{Decision: DecisionBlock},
					{Decision: DecisionBlock},
				},
			},
			"BLOCKED: 2",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := FormatEnforcementResult(tt.result)
			if len(got) == 0 {
				t.Fatal("FormatEnforcementResult returned empty string")
			}
			if !containsSubstring(got, tt.contains) {
				t.Errorf("FormatEnforcementResult() = %q, want to contain %q", got, tt.contains)
			}
		})
	}
}

// containsSubstring checks if s contains substr.
func containsSubstring(s, substr string) bool {
	return len(s) >= len(substr) && searchSubstring(s, substr)
}

func searchSubstring(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}

func TestDefaultEnforcementThresholds(t *testing.T) {
	thresholds := DefaultEnforcementThresholds()

	if thresholds == nil {
		t.Fatal("DefaultEnforcementThresholds() returned nil")
	}
	if len(thresholds.SeverityDefaults) != 4 {
		t.Errorf("expected 4 severity defaults, got %d", len(thresholds.SeverityDefaults))
	}
	if len(thresholds.Rules) == 0 {
		t.Error("expected at least one specific rule")
	}
}
