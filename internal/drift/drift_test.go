package drift

import (
	"math"
	"testing"

	"github.com/Kubedoll-Heavy-Industries/agentcontainers/internal/skillbom"
)

// baseSkillBOM returns a baseline SkillBOM for test comparisons.
func baseSkillBOM() *skillbom.SkillBOM {
	return &skillbom.SkillBOM{
		Format:       skillbom.Format,
		SkillName:    "code-review",
		Version:      "1.0.0",
		Description:  "Reviews code changes and provides feedback on style, bugs, and best practices",
		Capabilities: []string{"filesystem.read", "git.diff", "git.log"},
		ContentHash:  "sha256:aaa111",
		Components:   5,
	}
}

func TestDiffSkillBOM_IdenticalBOMs(t *testing.T) {
	old := baseSkillBOM()
	new := baseSkillBOM()

	report := DiffSkillBOM(old, new)

	if len(report.Signals) != 0 {
		t.Errorf("expected 0 signals for identical BOMs, got %d", len(report.Signals))
		for _, s := range report.Signals {
			t.Logf("  %s [%s] %s", s.Severity, s.Kind, s.Description)
		}
	}
	if report.MaxSeverity != "" {
		t.Errorf("MaxSeverity = %q, want empty string for no signals", report.MaxSeverity)
	}
	if report.HasHighOrCritical() {
		t.Error("HasHighOrCritical() should be false for identical BOMs")
	}
}

func TestDiffSkillBOM_CapabilityEscalation(t *testing.T) {
	old := baseSkillBOM()
	new := baseSkillBOM()
	new.Capabilities = append(new.Capabilities, "network.egress")
	new.ContentHash = "sha256:bbb222" // hash changes too

	report := DiffSkillBOM(old, new)

	// Should have critical signal for dangerous capability.
	capSignals := report.SignalsByKind(KindCapabilityAdded)
	if len(capSignals) != 1 {
		t.Fatalf("expected 1 capability-added signal, got %d", len(capSignals))
	}
	if capSignals[0].Severity != SeverityCritical {
		t.Errorf("network.egress should be critical, got %s", capSignals[0].Severity)
	}
	if capSignals[0].NewValue != "network.egress" {
		t.Errorf("NewValue = %q, want %q", capSignals[0].NewValue, "network.egress")
	}
	if !report.HasHighOrCritical() {
		t.Error("HasHighOrCritical() should be true for dangerous capability addition")
	}
}

func TestDiffSkillBOM_NonDangerousCapabilityAdded(t *testing.T) {
	old := baseSkillBOM()
	new := baseSkillBOM()
	new.Capabilities = append(new.Capabilities, "git.blame")
	new.ContentHash = "sha256:bbb222"

	report := DiffSkillBOM(old, new)

	capSignals := report.SignalsByKind(KindCapabilityAdded)
	if len(capSignals) != 1 {
		t.Fatalf("expected 1 capability-added signal, got %d", len(capSignals))
	}
	// git.blame is not dangerous -- should be high (escalation) but not critical.
	if capSignals[0].Severity != SeverityHigh {
		t.Errorf("non-dangerous capability addition should be high, got %s", capSignals[0].Severity)
	}
}

func TestDiffSkillBOM_CapabilityRemoved(t *testing.T) {
	old := baseSkillBOM()
	new := baseSkillBOM()
	new.Capabilities = []string{"filesystem.read"} // removed git.diff and git.log
	new.ContentHash = "sha256:bbb222"

	report := DiffSkillBOM(old, new)

	removedSignals := report.SignalsByKind(KindCapabilityRemoved)
	if len(removedSignals) != 2 {
		t.Fatalf("expected 2 capability-removed signals, got %d", len(removedSignals))
	}
	// Removed capabilities are low severity.
	for _, s := range removedSignals {
		if s.Severity != SeverityLow {
			t.Errorf("capability removal should be low, got %s for %s", s.Severity, s.OldValue)
		}
	}
}

func TestDiffSkillBOM_MultipleCapabilityChanges(t *testing.T) {
	old := baseSkillBOM()
	new := baseSkillBOM()
	// Remove git.log, add network.egress and process.exec.
	new.Capabilities = []string{"filesystem.read", "git.diff", "network.egress", "process.exec"}
	new.ContentHash = "sha256:bbb222"

	report := DiffSkillBOM(old, new)

	added := report.SignalsByKind(KindCapabilityAdded)
	removed := report.SignalsByKind(KindCapabilityRemoved)

	if len(added) != 2 {
		t.Errorf("expected 2 capabilities added, got %d", len(added))
	}
	if len(removed) != 1 {
		t.Errorf("expected 1 capability removed, got %d", len(removed))
	}
	if report.MaxSeverity != SeverityCritical {
		t.Errorf("MaxSeverity = %q, want critical (network.egress + process.exec)", report.MaxSeverity)
	}
}

func TestDiffSkillBOM_DescriptionDrasticallyChanged(t *testing.T) {
	old := baseSkillBOM()
	new := baseSkillBOM()
	// Use a completely unrelated description to ensure Jaro-Winkler similarity < 0.6.
	new.Description = "XYZ quantum flux harmonizer for plutonium neutron wave oscillation"
	new.ContentHash = "sha256:bbb222"

	report := DiffSkillBOM(old, new)

	descSignals := report.SignalsByKind(KindDescriptionChange)
	if len(descSignals) != 1 {
		t.Fatalf("expected 1 description-changed signal, got %d", len(descSignals))
	}
	// Drastically different descriptions should be high severity.
	if descSignals[0].Severity != SeverityHigh {
		t.Errorf("drastic description change should be high, got %s", descSignals[0].Severity)
	}
}

func TestDiffSkillBOM_DescriptionSlightlyChanged(t *testing.T) {
	old := baseSkillBOM()
	new := baseSkillBOM()
	new.Description = "Reviews code changes and provides feedback on style, bugs, and best practices." // added period
	new.ContentHash = "sha256:bbb222"

	report := DiffSkillBOM(old, new)

	descSignals := report.SignalsByKind(KindDescriptionChange)
	if len(descSignals) != 1 {
		t.Fatalf("expected 1 description-changed signal, got %d", len(descSignals))
	}
	if descSignals[0].Severity != SeverityLow {
		t.Errorf("slight description change should be low, got %s", descSignals[0].Severity)
	}
}

func TestDiffSkillBOM_DescriptionRemoved(t *testing.T) {
	old := baseSkillBOM()
	new := baseSkillBOM()
	new.Description = ""
	new.ContentHash = "sha256:bbb222"

	report := DiffSkillBOM(old, new)

	descSignals := report.SignalsByKind(KindDescriptionChange)
	if len(descSignals) != 1 {
		t.Fatalf("expected 1 description-changed signal, got %d", len(descSignals))
	}
	if descSignals[0].Severity != SeverityHigh {
		t.Errorf("description removal should be high, got %s", descSignals[0].Severity)
	}
}

func TestDiffSkillBOM_DescriptionAdded(t *testing.T) {
	old := baseSkillBOM()
	old.Description = ""
	new := baseSkillBOM()
	new.ContentHash = "sha256:bbb222"

	report := DiffSkillBOM(old, new)

	descSignals := report.SignalsByKind(KindDescriptionChange)
	if len(descSignals) != 1 {
		t.Fatalf("expected 1 description-changed signal, got %d", len(descSignals))
	}
	if descSignals[0].Severity != SeverityMedium {
		t.Errorf("description addition should be medium, got %s", descSignals[0].Severity)
	}
}

func TestDiffSkillBOM_NameChanged(t *testing.T) {
	old := baseSkillBOM()
	new := baseSkillBOM()
	new.SkillName = "data-exfiltrator"
	new.ContentHash = "sha256:bbb222"

	report := DiffSkillBOM(old, new)

	nameSignals := report.SignalsByKind(KindNameChange)
	if len(nameSignals) != 1 {
		t.Fatalf("expected 1 name-changed signal, got %d", len(nameSignals))
	}
	if nameSignals[0].Severity != SeverityHigh {
		t.Errorf("name change should be high, got %s", nameSignals[0].Severity)
	}
	if nameSignals[0].OldValue != "code-review" || nameSignals[0].NewValue != "data-exfiltrator" {
		t.Errorf("wrong old/new values: %q -> %q", nameSignals[0].OldValue, nameSignals[0].NewValue)
	}
}

func TestDiffSkillBOM_VersionChanged(t *testing.T) {
	old := baseSkillBOM()
	new := baseSkillBOM()
	new.Version = "1.1.0"

	report := DiffSkillBOM(old, new)

	verSignals := report.SignalsByKind(KindVersionChange)
	if len(verSignals) != 1 {
		t.Fatalf("expected 1 version-changed signal, got %d", len(verSignals))
	}
	if verSignals[0].Severity != SeverityLow {
		t.Errorf("version change should be low, got %s", verSignals[0].Severity)
	}
}

func TestDiffSkillBOM_ComponentCountIncreasedSmall(t *testing.T) {
	old := baseSkillBOM()
	new := baseSkillBOM()
	new.Components = 8 // +3

	report := DiffSkillBOM(old, new)

	countSignals := report.SignalsByKind(KindComponentCountUp)
	if len(countSignals) != 1 {
		t.Fatalf("expected 1 component-count-increased signal, got %d", len(countSignals))
	}
	if countSignals[0].Severity != SeverityLow {
		t.Errorf("small component increase should be low, got %s", countSignals[0].Severity)
	}
}

func TestDiffSkillBOM_ComponentCountIncreasedLarge(t *testing.T) {
	old := baseSkillBOM()
	new := baseSkillBOM()
	new.Components = 30 // +25

	report := DiffSkillBOM(old, new)

	countSignals := report.SignalsByKind(KindComponentCountUp)
	if len(countSignals) != 1 {
		t.Fatalf("expected 1 component-count-increased signal, got %d", len(countSignals))
	}
	if countSignals[0].Severity != SeverityHigh {
		t.Errorf("large component increase (25) should be high, got %s", countSignals[0].Severity)
	}
}

func TestDiffSkillBOM_ComponentCountDecreased(t *testing.T) {
	old := baseSkillBOM()
	new := baseSkillBOM()
	new.Components = 2 // -3

	report := DiffSkillBOM(old, new)

	countSignals := report.SignalsByKind(KindComponentCountDn)
	if len(countSignals) != 1 {
		t.Fatalf("expected 1 component-count-decreased signal, got %d", len(countSignals))
	}
	if countSignals[0].Severity != SeverityLow {
		t.Errorf("small component decrease should be low, got %s", countSignals[0].Severity)
	}
}

func TestDiffSkillBOM_ContentHashBreaking(t *testing.T) {
	old := baseSkillBOM()
	new := baseSkillBOM()
	new.ContentHash = "sha256:completely_different_hash"

	report := DiffSkillBOM(old, new)

	hashSignals := report.SignalsByKind(KindContentHashChange)
	if len(hashSignals) != 1 {
		t.Fatalf("expected 1 content-hash-changed signal, got %d", len(hashSignals))
	}
	// Without embeddings, content hash change = distance 1.0 = breaking.
	if hashSignals[0].Severity != SeverityCritical {
		t.Errorf("breaking content hash change should be critical, got %s", hashSignals[0].Severity)
	}
}

func TestDiffSkillBOM_SemanticDriftSignal(t *testing.T) {
	old := baseSkillBOM()
	new := baseSkillBOM()
	new.ContentHash = "sha256:totally_different"

	report := DiffSkillBOM(old, new)

	driftSignals := report.SignalsByKind(KindSemanticDrift)
	if len(driftSignals) != 1 {
		t.Fatalf("expected 1 semantic-drift signal, got %d", len(driftSignals))
	}
	// Content hash mode + hashes differ = distance 1.0 = breaking.
	if driftSignals[0].Severity != SeverityCritical {
		t.Errorf("breaking drift should produce critical signal, got %s", driftSignals[0].Severity)
	}
}

func TestDiffSkillBOM_WithEmbeddings_SimilarVectors(t *testing.T) {
	old := baseSkillBOM()
	old.EmbeddingVector = []float32{1, 0, 0}
	old.EmbeddingModel = "nomic-embed-text-v1.5"

	new := baseSkillBOM()
	new.ContentHash = "sha256:bbb222"
	new.EmbeddingVector = []float32{0.99, 0.01, 0}
	new.EmbeddingModel = "nomic-embed-text-v1.5"

	report := DiffSkillBOM(old, new)

	// Embedding distance should be small (patch level).
	if report.DriftResult.Distance >= 0.05 {
		t.Errorf("Distance = %f, expected < 0.05 for similar vectors", report.DriftResult.Distance)
	}

	// Content hash changed but drift is patch -- should be medium severity.
	hashSignals := report.SignalsByKind(KindContentHashChange)
	if len(hashSignals) != 1 {
		t.Fatalf("expected 1 content-hash-changed signal, got %d", len(hashSignals))
	}
	// patch classification => medium severity for hash change.
	if hashSignals[0].Severity != SeverityMedium {
		t.Errorf("patch-level hash change should be medium, got %s", hashSignals[0].Severity)
	}

	// Should NOT emit semantic-drift signal for patch-level.
	driftSignals := report.SignalsByKind(KindSemanticDrift)
	if len(driftSignals) != 0 {
		t.Errorf("expected 0 semantic-drift signals for patch-level drift, got %d", len(driftSignals))
	}
}

func TestDiffSkillBOM_RugPullScenario(t *testing.T) {
	// Simulates a supply-chain attack: trusted tool suddenly requests
	// dangerous capabilities, changes description, and has high semantic drift.
	old := baseSkillBOM()
	new := &skillbom.SkillBOM{
		Format:       skillbom.Format,
		SkillName:    "code-review",
		Version:      "1.0.1", // innocent-looking patch version
		Description:  "Sends code to external analysis service for deep review",
		Capabilities: []string{"filesystem.read", "git.diff", "git.log", "network.egress", "secrets.read"},
		ContentHash:  "sha256:zzz999",
		Components:   15,
	}

	report := DiffSkillBOM(old, new)

	if !report.HasHighOrCritical() {
		t.Fatal("rug pull scenario should have high or critical signals")
	}

	// Should detect: capability escalation (2 dangerous), description change, component increase.
	capAdded := report.SignalsByKind(KindCapabilityAdded)
	if len(capAdded) != 2 {
		t.Errorf("expected 2 capability-added signals, got %d", len(capAdded))
	}

	// Both network.egress and secrets.read are dangerous.
	critCount := 0
	for _, s := range capAdded {
		if s.Severity == SeverityCritical {
			critCount++
		}
	}
	if critCount != 2 {
		t.Errorf("expected 2 critical capability signals, got %d", critCount)
	}

	if report.MaxSeverity != SeverityCritical {
		t.Errorf("MaxSeverity = %q, want critical", report.MaxSeverity)
	}
}

func TestDiffSkillBOM_SignalsSortedBySeverity(t *testing.T) {
	old := baseSkillBOM()
	new := &skillbom.SkillBOM{
		Format:       skillbom.Format,
		SkillName:    "different-name",
		Version:      "2.0.0",
		Description:  "Completely different description about something else entirely unrelated",
		Capabilities: []string{"network.egress"},
		ContentHash:  "sha256:zzz",
		Components:   50,
	}

	report := DiffSkillBOM(old, new)

	// Verify signals are sorted: critical first, then high, medium, low.
	prevRank := 100
	for i, s := range report.Signals {
		rank := severityRank(s.Severity)
		if rank > prevRank {
			t.Errorf("signal %d has severity %s (rank %d) after severity rank %d -- not properly sorted",
				i, s.Severity, rank, prevRank)
		}
		prevRank = rank
	}
}

func TestReport_SignalsByKind(t *testing.T) {
	report := &Report{
		Signals: []DriftSignal{
			{Kind: KindCapabilityAdded, Description: "a"},
			{Kind: KindCapabilityRemoved, Description: "b"},
			{Kind: KindCapabilityAdded, Description: "c"},
			{Kind: KindDescriptionChange, Description: "d"},
		},
	}

	added := report.SignalsByKind(KindCapabilityAdded)
	if len(added) != 2 {
		t.Errorf("expected 2 capability-added signals, got %d", len(added))
	}

	removed := report.SignalsByKind(KindCapabilityRemoved)
	if len(removed) != 1 {
		t.Errorf("expected 1 capability-removed signal, got %d", len(removed))
	}

	unknown := report.SignalsByKind("nonexistent-kind")
	if len(unknown) != 0 {
		t.Errorf("expected 0 signals for nonexistent kind, got %d", len(unknown))
	}
}

func TestReport_HasHighOrCritical(t *testing.T) {
	tests := []struct {
		name string
		max  Severity
		want bool
	}{
		{"low", SeverityLow, false},
		{"medium", SeverityMedium, false},
		{"high", SeverityHigh, true},
		{"critical", SeverityCritical, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := &Report{MaxSeverity: tt.max}
			if got := r.HasHighOrCritical(); got != tt.want {
				t.Errorf("HasHighOrCritical() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestSeverityRank(t *testing.T) {
	tests := []struct {
		sev  Severity
		rank int
	}{
		{SeverityLow, 0},
		{SeverityMedium, 1},
		{SeverityHigh, 2},
		{SeverityCritical, 3},
		{Severity("unknown"), -1},
	}
	for _, tt := range tests {
		t.Run(string(tt.sev), func(t *testing.T) {
			if got := severityRank(tt.sev); got != tt.rank {
				t.Errorf("severityRank(%q) = %d, want %d", tt.sev, got, tt.rank)
			}
		})
	}
}

func TestIsDangerousCapability(t *testing.T) {
	tests := []struct {
		cap  string
		want bool
	}{
		{"network.egress", true},
		{"network.listen", true},
		{"filesystem.write", true},
		{"filesystem.read", false},
		{"process.exec", true},
		{"secrets.read", true},
		{"credentials", true},
		{"credentials.rotate", true},
		{"shell.exec", true},
		{"host.access", true},
		{"git.diff", false},
		{"git.log", false},
		{"filesystem.read", false},
	}
	for _, tt := range tests {
		t.Run(tt.cap, func(t *testing.T) {
			if got := isDangerousCapability(tt.cap); got != tt.want {
				t.Errorf("isDangerousCapability(%q) = %v, want %v", tt.cap, got, tt.want)
			}
		})
	}
}

func TestTruncate(t *testing.T) {
	tests := []struct {
		input string
		n     int
		want  string
	}{
		{"hello", 10, "hello"},
		{"hello", 5, "hello"},
		{"hello world", 5, "hello..."},
		{"", 5, ""},
		{"abc", 0, "..."},
	}
	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			if got := truncate(tt.input, tt.n); got != tt.want {
				t.Errorf("truncate(%q, %d) = %q, want %q", tt.input, tt.n, got, tt.want)
			}
		})
	}
}

func TestJaroWinklerSimilarity(t *testing.T) {
	tests := []struct {
		name    string
		s1, s2  string
		wantMin float64
		wantMax float64
	}{
		{"identical", "hello", "hello", 1.0, 1.0},
		{"empty both", "", "", 1.0, 1.0},
		{"empty one", "hello", "", 0.0, 0.0},
		{"similar", "martha", "marhta", 0.95, 1.0},
		{"very different", "hello", "zzzzz", 0.0, 0.3},
		{"completely different", "abc", "xyz", 0.0, 0.1},
		{"long similar", "the quick brown fox", "the quick brown fog", 0.95, 1.0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := jaroWinklerSimilarity(tt.s1, tt.s2)
			if got < tt.wantMin || got > tt.wantMax {
				t.Errorf("jaroWinklerSimilarity(%q, %q) = %f, want in [%f, %f]",
					tt.s1, tt.s2, got, tt.wantMin, tt.wantMax)
			}
		})
	}
}

func TestJaroSimilarity_Symmetry(t *testing.T) {
	pairs := [][2]string{
		{"hello", "world"},
		{"martha", "marhta"},
		{"abc", "xyz"},
		{"", "test"},
	}
	for _, p := range pairs {
		a := jaroSimilarity(p[0], p[1])
		b := jaroSimilarity(p[1], p[0])
		if math.Abs(a-b) > 1e-10 {
			t.Errorf("jaroSimilarity(%q, %q) = %f but reversed = %f (not symmetric)",
				p[0], p[1], a, b)
		}
	}
}

func TestDetectCapabilityChanges_NoChanges(t *testing.T) {
	caps := []string{"a", "b", "c"}
	signals := detectCapabilityChanges(caps, caps)
	if len(signals) != 0 {
		t.Errorf("expected 0 signals for identical capabilities, got %d", len(signals))
	}
}

func TestDetectCapabilityChanges_EmptyToSome(t *testing.T) {
	signals := detectCapabilityChanges(nil, []string{"filesystem.read", "git.log"})
	if len(signals) != 2 {
		t.Fatalf("expected 2 signals, got %d", len(signals))
	}
	for _, s := range signals {
		if s.Kind != KindCapabilityAdded {
			t.Errorf("expected capability-added, got %s", s.Kind)
		}
	}
}

func TestDetectCapabilityChanges_SomeToEmpty(t *testing.T) {
	signals := detectCapabilityChanges([]string{"filesystem.read", "git.log"}, nil)
	if len(signals) != 2 {
		t.Fatalf("expected 2 signals, got %d", len(signals))
	}
	for _, s := range signals {
		if s.Kind != KindCapabilityRemoved {
			t.Errorf("expected capability-removed, got %s", s.Kind)
		}
	}
}

func TestDetectComponentCountChanges_NoChange(t *testing.T) {
	signals := detectComponentCountChanges(5, 5)
	if len(signals) != 0 {
		t.Errorf("expected 0 signals for same count, got %d", len(signals))
	}
}

func TestDetectComponentCountChanges_MediumIncrease(t *testing.T) {
	signals := detectComponentCountChanges(5, 15) // +10
	if len(signals) != 1 {
		t.Fatalf("expected 1 signal, got %d", len(signals))
	}
	if signals[0].Severity != SeverityMedium {
		t.Errorf("increase of 10 should be medium, got %s", signals[0].Severity)
	}
}

func TestDetectComponentCountChanges_LargeDecrease(t *testing.T) {
	signals := detectComponentCountChanges(20, 10) // -10
	if len(signals) != 1 {
		t.Fatalf("expected 1 signal, got %d", len(signals))
	}
	if signals[0].Severity != SeverityMedium {
		t.Errorf("decrease of 10 should be medium, got %s", signals[0].Severity)
	}
}

func TestDiffSkillBOMWithThresholds_CustomThresholds(t *testing.T) {
	// Use vectors with moderate angular difference and tight thresholds
	// to verify custom thresholds are respected.
	// Vectors: {1,0,0} vs {0.7,0.7,0} have cosine distance ~0.01.
	old := baseSkillBOM()
	old.EmbeddingVector = []float32{1, 0, 0}
	old.EmbeddingModel = "test"

	new := baseSkillBOM()
	new.ContentHash = "sha256:bbb222"
	new.EmbeddingVector = []float32{0.7, 0.7, 0} // ~45 degrees off
	new.EmbeddingModel = "test"

	tight := skillbom.DriftThresholds{
		Patch:    0.001,
		Minor:    0.005,
		Major:    0.01,
		Breaking: 0.01,
	}

	report := DiffSkillBOMWithThresholds(old, new, tight)

	// The distance (~0.29 for these vectors) should easily exceed the
	// tight breaking threshold of 0.01.
	if report.DriftResult.Classification != skillbom.DriftBreaking {
		t.Errorf("Classification = %q (distance=%.4f), want breaking with tight thresholds",
			report.DriftResult.Classification, report.DriftResult.Distance)
	}
}
