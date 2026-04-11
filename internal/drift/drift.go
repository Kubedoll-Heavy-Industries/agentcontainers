// Package drift provides semantic drift detection for agent skills and tools.
//
// Drift detection compares two versions of a SkillBOM to identify suspicious
// changes that may indicate supply-chain compromise (rug pulls). It produces
// a list of DriftSignal values, each categorized by severity and kind, that
// can be used to block, warn, or auto-approve skill updates.
//
// The package builds on top of the low-level skillbom.ComputeDrift distance
// computation, adding structured signal decomposition that explains *why*
// drift was flagged, not just *how much* drift occurred.
package drift

import (
	"fmt"
	"sort"
	"strings"

	"github.com/Kubedoll-Heavy-Industries/agentcontainers/internal/skillbom"
)

// Severity categorizes the risk level of a drift signal.
type Severity string

const (
	SeverityLow      Severity = "low"
	SeverityMedium   Severity = "medium"
	SeverityHigh     Severity = "high"
	SeverityCritical Severity = "critical"
)

// Kind identifies the type of change that produced a drift signal.
type Kind string

const (
	KindCapabilityAdded   Kind = "capability-added"
	KindCapabilityRemoved Kind = "capability-removed"
	KindDescriptionChange Kind = "description-changed"
	KindNameChange        Kind = "name-changed"
	KindVersionChange     Kind = "version-changed"
	KindContentHashChange Kind = "content-hash-changed"
	KindComponentCountUp  Kind = "component-count-increased"
	KindComponentCountDn  Kind = "component-count-decreased"
	KindSemanticDrift     Kind = "semantic-drift"
)

// DriftSignal represents a single detected change between two SkillBOM versions.
type DriftSignal struct {
	// Severity is the risk classification of this signal.
	Severity Severity `json:"severity"`

	// Kind identifies the category of change.
	Kind Kind `json:"kind"`

	// Description is a human-readable explanation of the signal.
	Description string `json:"description"`

	// OldValue is the previous value (if applicable).
	OldValue string `json:"oldValue,omitempty"`

	// NewValue is the new value (if applicable).
	NewValue string `json:"newValue,omitempty"`
}

// Report is the aggregated result of comparing two SkillBOM versions.
type Report struct {
	// Signals is the ordered list of detected drift signals.
	Signals []DriftSignal `json:"signals"`

	// DriftResult is the underlying distance computation from skillbom.
	DriftResult *skillbom.DriftResult `json:"driftResult"`

	// MaxSeverity is the highest severity among all signals.
	MaxSeverity Severity `json:"maxSeverity"`
}

// HasHighOrCritical returns true if any signal has high or critical severity.
func (r *Report) HasHighOrCritical() bool {
	return r.MaxSeverity == SeverityHigh || r.MaxSeverity == SeverityCritical
}

// SignalsByKind returns all signals matching the given kind.
func (r *Report) SignalsByKind(kind Kind) []DriftSignal {
	var result []DriftSignal
	for _, s := range r.Signals {
		if s.Kind == kind {
			result = append(result, s)
		}
	}
	return result
}

// severityRank returns a numeric rank for severity comparison.
func severityRank(s Severity) int {
	switch s {
	case SeverityLow:
		return 0
	case SeverityMedium:
		return 1
	case SeverityHigh:
		return 2
	case SeverityCritical:
		return 3
	default:
		return -1
	}
}

// DiffSkillBOM compares two SkillBOMs and returns a detailed drift Report.
// The old parameter is the previously approved version; new is the candidate update.
// Uses default drift thresholds from skillbom.DefaultThresholds.
func DiffSkillBOM(old, new *skillbom.SkillBOM) *Report {
	return DiffSkillBOMWithThresholds(old, new, skillbom.DefaultThresholds)
}

// DiffSkillBOMWithThresholds compares two SkillBOMs using custom drift thresholds.
func DiffSkillBOMWithThresholds(old, new *skillbom.SkillBOM, thresholds skillbom.DriftThresholds) *Report {
	dr := skillbom.ComputeDriftWithThresholds(old, new, thresholds)

	var signals []DriftSignal

	// 1. Check for name changes.
	if old.SkillName != new.SkillName {
		signals = append(signals, DriftSignal{
			Severity:    SeverityHigh,
			Kind:        KindNameChange,
			Description: fmt.Sprintf("skill name changed from %q to %q", old.SkillName, new.SkillName),
			OldValue:    old.SkillName,
			NewValue:    new.SkillName,
		})
	}

	// 2. Check for version changes.
	if old.Version != new.Version {
		signals = append(signals, DriftSignal{
			Severity:    SeverityLow,
			Kind:        KindVersionChange,
			Description: fmt.Sprintf("version changed from %q to %q", old.Version, new.Version),
			OldValue:    old.Version,
			NewValue:    new.Version,
		})
	}

	// 3. Check for description changes.
	signals = append(signals, detectDescriptionChange(old.Description, new.Description)...)

	// 4. Check for capability additions (escalation).
	signals = append(signals, detectCapabilityChanges(old.Capabilities, new.Capabilities)...)

	// 5. Check for component count changes.
	signals = append(signals, detectComponentCountChanges(old.Components, new.Components)...)

	// 6. Check content hash changes.
	if old.ContentHash != new.ContentHash {
		sev := SeverityMedium
		switch dr.Classification {
		case skillbom.DriftBreaking:
			sev = SeverityCritical
		case skillbom.DriftMajor:
			sev = SeverityHigh
		}
		signals = append(signals, DriftSignal{
			Severity:    sev,
			Kind:        KindContentHashChange,
			Description: fmt.Sprintf("semantic content hash changed (distance: %.4f, classification: %s)", dr.Distance, dr.Classification),
			OldValue:    old.ContentHash,
			NewValue:    new.ContentHash,
		})
	}

	// 7. Emit overall semantic drift signal if distance is non-trivial.
	if dr.Distance >= thresholds.Minor {
		sev := SeverityMedium
		desc := fmt.Sprintf("semantic drift distance %.4f classified as %s", dr.Distance, dr.Classification)
		switch dr.Classification {
		case skillbom.DriftBreaking:
			sev = SeverityCritical
			desc += " -- potential rug pull"
		case skillbom.DriftMajor:
			sev = SeverityHigh
			desc += " -- requires human review"
		}
		if dr.EmbeddingUsed {
			desc += " (embedding-based)"
		} else {
			desc += " (content-hash-based)"
		}
		signals = append(signals, DriftSignal{
			Severity:    sev,
			Kind:        KindSemanticDrift,
			Description: desc,
			OldValue:    fmt.Sprintf("%.4f", 0.0),
			NewValue:    fmt.Sprintf("%.4f", dr.Distance),
		})
	}

	// Compute max severity. Default to empty when no signals are present,
	// so callers can distinguish "no issues" from "one low-severity issue".
	var maxSev Severity
	for _, s := range signals {
		if severityRank(s.Severity) > severityRank(maxSev) {
			maxSev = s.Severity
		}
	}

	// Sort signals by severity (critical first) then by kind.
	sort.Slice(signals, func(i, j int) bool {
		ri, rj := severityRank(signals[i].Severity), severityRank(signals[j].Severity)
		if ri != rj {
			return ri > rj // higher severity first
		}
		return signals[i].Kind < signals[j].Kind
	})

	return &Report{
		Signals:     signals,
		DriftResult: dr,
		MaxSeverity: maxSev,
	}
}

// detectDescriptionChange compares old and new descriptions and returns
// appropriate signals based on the magnitude of change.
func detectDescriptionChange(oldDesc, newDesc string) []DriftSignal {
	if oldDesc == newDesc {
		return nil
	}

	// Both empty or both set -- compute similarity.
	if oldDesc == "" && newDesc != "" {
		return []DriftSignal{{
			Severity:    SeverityMedium,
			Kind:        KindDescriptionChange,
			Description: "description added where none existed before",
			NewValue:    truncate(newDesc, 200),
		}}
	}
	if oldDesc != "" && newDesc == "" {
		return []DriftSignal{{
			Severity:    SeverityHigh,
			Kind:        KindDescriptionChange,
			Description: "description removed entirely",
			OldValue:    truncate(oldDesc, 200),
		}}
	}

	// Both non-empty -- assess magnitude of change.
	ratio := jaroWinklerSimilarity(oldDesc, newDesc)
	var sev Severity
	var desc string

	switch {
	case ratio >= 0.9:
		sev = SeverityLow
		desc = fmt.Sprintf("description changed slightly (similarity: %.2f)", ratio)
	case ratio >= 0.6:
		sev = SeverityMedium
		desc = fmt.Sprintf("description changed moderately (similarity: %.2f)", ratio)
	default:
		sev = SeverityHigh
		desc = fmt.Sprintf("description changed drastically (similarity: %.2f)", ratio)
	}

	return []DriftSignal{{
		Severity:    sev,
		Kind:        KindDescriptionChange,
		Description: desc,
		OldValue:    truncate(oldDesc, 200),
		NewValue:    truncate(newDesc, 200),
	}}
}

// detectCapabilityChanges compares old and new capability lists.
func detectCapabilityChanges(oldCaps, newCaps []string) []DriftSignal {
	oldSet := make(map[string]bool, len(oldCaps))
	for _, c := range oldCaps {
		oldSet[c] = true
	}
	newSet := make(map[string]bool, len(newCaps))
	for _, c := range newCaps {
		newSet[c] = true
	}

	var signals []DriftSignal

	// Capabilities added (escalation).
	var added []string
	for _, c := range newCaps {
		if !oldSet[c] {
			added = append(added, c)
		}
	}
	for _, c := range added {
		sev := SeverityHigh
		desc := fmt.Sprintf("new capability requested: %s", c)

		// Certain capabilities are especially dangerous.
		if isDangerousCapability(c) {
			sev = SeverityCritical
			desc = fmt.Sprintf("dangerous capability added: %s", c)
		}

		signals = append(signals, DriftSignal{
			Severity:    sev,
			Kind:        KindCapabilityAdded,
			Description: desc,
			NewValue:    c,
		})
	}

	// Capabilities removed (may indicate scope reduction or suspicious refactoring).
	var removed []string
	for _, c := range oldCaps {
		if !newSet[c] {
			removed = append(removed, c)
		}
	}
	for _, c := range removed {
		signals = append(signals, DriftSignal{
			Severity:    SeverityLow,
			Kind:        KindCapabilityRemoved,
			Description: fmt.Sprintf("capability removed: %s", c),
			OldValue:    c,
		})
	}

	return signals
}

// detectComponentCountChanges emits signals when the number of components
// changes significantly.
func detectComponentCountChanges(oldCount, newCount int) []DriftSignal {
	if oldCount == newCount {
		return nil
	}

	diff := newCount - oldCount
	if diff > 0 {
		sev := SeverityLow
		if diff > 5 {
			sev = SeverityMedium
		}
		if diff > 20 {
			sev = SeverityHigh
		}
		return []DriftSignal{{
			Severity:    sev,
			Kind:        KindComponentCountUp,
			Description: fmt.Sprintf("component count increased from %d to %d (+%d)", oldCount, newCount, diff),
			OldValue:    fmt.Sprintf("%d", oldCount),
			NewValue:    fmt.Sprintf("%d", newCount),
		}}
	}

	// Decrease.
	absDiff := -diff
	sev := SeverityLow
	if absDiff > 5 {
		sev = SeverityMedium
	}
	return []DriftSignal{{
		Severity:    sev,
		Kind:        KindComponentCountDn,
		Description: fmt.Sprintf("component count decreased from %d to %d (-%d)", oldCount, newCount, absDiff),
		OldValue:    fmt.Sprintf("%d", oldCount),
		NewValue:    fmt.Sprintf("%d", newCount),
	}}
}

// isDangerousCapability returns true for capabilities that represent
// significant security-sensitive operations.
func isDangerousCapability(cap string) bool {
	dangerous := []string{
		"network.egress",
		"network.listen",
		"filesystem.write",
		"process.exec",
		"secrets.read",
		"credentials",
		"shell.exec",
		"host.access",
	}
	lower := strings.ToLower(cap)
	for _, d := range dangerous {
		if lower == d || strings.HasPrefix(lower, d+".") {
			return true
		}
	}
	return false
}

// truncate shortens a string to at most n runes, appending "..." if truncated.
func truncate(s string, n int) string {
	runes := []rune(s)
	if len(runes) <= n {
		return s
	}
	return string(runes[:n]) + "..."
}

// jaroWinklerSimilarity computes the Jaro-Winkler similarity between two strings.
// Returns a value in [0.0, 1.0] where 1.0 means identical strings.
// This is used for approximate description comparison without external dependencies.
func jaroWinklerSimilarity(s1, s2 string) float64 {
	jaro := jaroSimilarity(s1, s2)
	if jaro == 0 {
		return 0
	}

	// Compute common prefix length (up to 4 characters).
	prefix := 0
	r1, r2 := []rune(s1), []rune(s2)
	maxPrefix := 4
	if len(r1) < maxPrefix {
		maxPrefix = len(r1)
	}
	if len(r2) < maxPrefix {
		maxPrefix = len(r2)
	}
	for i := 0; i < maxPrefix; i++ {
		if r1[i] == r2[i] {
			prefix++
		} else {
			break
		}
	}

	// Winkler modification: boost similarity for common prefix.
	const p = 0.1 // standard scaling factor
	return jaro + float64(prefix)*p*(1-jaro)
}

// jaroSimilarity computes the Jaro similarity between two strings.
func jaroSimilarity(s1, s2 string) float64 {
	r1, r2 := []rune(s1), []rune(s2)
	if len(r1) == 0 && len(r2) == 0 {
		return 1.0
	}
	if len(r1) == 0 || len(r2) == 0 {
		return 0.0
	}

	// Matching window.
	maxDist := len(r1)
	if len(r2) > maxDist {
		maxDist = len(r2)
	}
	maxDist = maxDist/2 - 1
	if maxDist < 0 {
		maxDist = 0
	}

	matched1 := make([]bool, len(r1))
	matched2 := make([]bool, len(r2))

	matches := 0
	transpositions := 0

	// Find matches.
	for i := range r1 {
		start := i - maxDist
		if start < 0 {
			start = 0
		}
		end := i + maxDist + 1
		if end > len(r2) {
			end = len(r2)
		}
		for j := start; j < end; j++ {
			if matched2[j] || r1[i] != r2[j] {
				continue
			}
			matched1[i] = true
			matched2[j] = true
			matches++
			break
		}
	}

	if matches == 0 {
		return 0.0
	}

	// Count transpositions.
	k := 0
	for i := range r1 {
		if !matched1[i] {
			continue
		}
		for !matched2[k] {
			k++
		}
		if r1[i] != r2[k] {
			transpositions++
		}
		k++
	}

	m := float64(matches)
	return (m/float64(len(r1)) + m/float64(len(r2)) + (m-float64(transpositions)/2)/m) / 3.0
}
