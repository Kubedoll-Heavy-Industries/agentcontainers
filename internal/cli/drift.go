package cli

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"

	"github.com/Kubedoll-Heavy-Industries/agentcontainers/internal/drift"
	"github.com/Kubedoll-Heavy-Industries/agentcontainers/internal/skillbom"
)

func newDriftCmd() *cobra.Command {
	var (
		outputJSON bool
		strict     bool
		enforce    bool
	)

	cmd := &cobra.Command{
		Use:   "drift <old-skillbom> <new-skillbom>",
		Short: "Detect semantic drift between two SkillBOM versions",
		Long: `Compare two SkillBOM JSON files and report semantic drift signals.

Drift detection identifies suspicious changes between skill versions that
may indicate supply-chain compromise (rug pulls). It checks for:

  - Capability escalation (new dangerous capabilities requested)
  - Description changes beyond a similarity threshold
  - Component count changes
  - Semantic content hash drift
  - Name and version changes

Each signal is assigned a severity (low/medium/high/critical) and a kind
that explains the nature of the change.

In strict mode (--strict), the command exits with code 1 if any high or
critical severity signals are detected. This is useful for CI pipelines.

In enforce mode (--enforce), threshold-based enforcement is applied:
  - Critical signals are blocked (exit code 1)
  - High signals require approval (exit code 2)
  - Medium signals generate a notice
  - Low signals are auto-approved

Examples:
  ac drift old-skillbom.json new-skillbom.json
  ac drift --strict old-skillbom.json new-skillbom.json
  ac drift --enforce old-skillbom.json new-skillbom.json
  ac drift --json old-skillbom.json new-skillbom.json`,
		Args: cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runDrift(cmd, args[0], args[1], outputJSON, strict, enforce)
		},
	}

	cmd.Flags().BoolVar(&outputJSON, "json", false, "Output drift report as JSON")
	cmd.Flags().BoolVar(&strict, "strict", false, "Exit with error on high/critical signals (for CI)")
	cmd.Flags().BoolVar(&enforce, "enforce", false, "Apply threshold-based enforcement (exit 1=blocked, 2=approval required)")

	return cmd
}

// driftExitError wraps a drift enforcement error with a specific exit code.
type driftExitError struct {
	code int
	msg  string
}

func (e *driftExitError) Error() string { return e.msg }
func (e *driftExitError) ExitCode() int { return e.code }

func runDrift(cmd *cobra.Command, oldPath, newPath string, outputJSON, strict, enforce bool) error {
	out := cmd.OutOrStdout()

	oldBOM, err := loadSkillBOM(oldPath)
	if err != nil {
		return fmt.Errorf("drift: loading old SkillBOM: %w", err)
	}

	newBOM, err := loadSkillBOM(newPath)
	if err != nil {
		return fmt.Errorf("drift: loading new SkillBOM: %w", err)
	}

	report := drift.DiffSkillBOM(oldBOM, newBOM)

	// Apply threshold enforcement if requested.
	var enfResult *drift.EnforcementResult
	if enforce {
		thresholds := drift.DefaultEnforcementThresholds()
		enfResult = drift.EnforceThresholds(report, thresholds)
	}

	if outputJSON {
		output := driftJSONOutput{
			Report: report,
		}
		if enfResult != nil {
			output.Enforcement = &driftJSONEnforcement{
				Decision:        enfResult.Decision,
				SignalDecisions: enfResult.SignalDecisions,
				Summary:         drift.FormatEnforcementResult(enfResult),
			}
		}
		enc := json.NewEncoder(out)
		enc.SetIndent("", "  ")
		if err := enc.Encode(output); err != nil {
			return fmt.Errorf("drift: encoding JSON: %w", err)
		}
	} else {
		printDriftReport(cmd, report, oldBOM, newBOM)
		if enfResult != nil {
			_, _ = fmt.Fprintf(out, "\nEnforcement: %s\n", drift.FormatEnforcementResult(enfResult))
		}
	}

	// Enforcement mode takes precedence over strict mode.
	if enforce && enfResult != nil {
		switch {
		case enfResult.Decision.IsBlocking():
			return &driftExitError{code: 1, msg: fmt.Sprintf("drift: %s", drift.FormatEnforcementResult(enfResult))}
		case enfResult.Decision.RequiresApproval():
			return &driftExitError{code: 2, msg: fmt.Sprintf("drift: %s", drift.FormatEnforcementResult(enfResult))}
		}
		return nil
	}

	if strict && report.HasHighOrCritical() {
		highCount := 0
		critCount := 0
		for _, s := range report.Signals {
			switch s.Severity {
			case drift.SeverityHigh:
				highCount++
			case drift.SeverityCritical:
				critCount++
			}
		}
		return fmt.Errorf("drift: %d critical and %d high severity signal(s) detected", critCount, highCount)
	}

	return nil
}

// driftJSONOutput is the combined JSON output for drift analysis.
type driftJSONOutput struct {
	Report      *drift.Report         `json:"report"`
	Enforcement *driftJSONEnforcement `json:"enforcement,omitempty"`
}

// driftJSONEnforcement holds the enforcement decision in JSON output.
type driftJSONEnforcement struct {
	Decision        drift.Decision         `json:"decision"`
	SignalDecisions []drift.SignalDecision `json:"signalDecisions"`
	Summary         string                 `json:"summary"`
}

func printDriftReport(cmd *cobra.Command, report *drift.Report, oldBOM, newBOM *skillbom.SkillBOM) {
	out := cmd.OutOrStdout()

	_, _ = fmt.Fprintf(out, "Drift Report: %s %s -> %s %s\n",
		oldBOM.SkillName, oldBOM.Version, newBOM.SkillName, newBOM.Version)
	_, _ = fmt.Fprintf(out, "Distance: %.4f  Classification: %s  Max Severity: %s\n",
		report.DriftResult.Distance, report.DriftResult.Classification, report.MaxSeverity)

	if report.DriftResult.EmbeddingUsed {
		_, _ = fmt.Fprintln(out, "Method: embedding-based (cosine distance)")
	} else {
		_, _ = fmt.Fprintln(out, "Method: content-hash-based (binary comparison)")
	}

	_, _ = fmt.Fprintln(out, strings.Repeat("-", 72))

	if len(report.Signals) == 0 {
		_, _ = fmt.Fprintln(out, "No drift signals detected. Skill update appears safe.")
		return
	}

	for i, signal := range report.Signals {
		marker := severityMarker(signal.Severity)
		_, _ = fmt.Fprintf(out, "%s [%s] %s: %s\n", marker, signal.Severity, signal.Kind, signal.Description)
		if signal.OldValue != "" {
			_, _ = fmt.Fprintf(out, "      old: %s\n", signal.OldValue)
		}
		if signal.NewValue != "" {
			_, _ = fmt.Fprintf(out, "      new: %s\n", signal.NewValue)
		}
		if i < len(report.Signals)-1 {
			_, _ = fmt.Fprintln(out)
		}
	}

	_, _ = fmt.Fprintf(out, "\n%s\n", strings.Repeat("-", 72))
	_, _ = fmt.Fprintf(out, "Total signals: %d  ", len(report.Signals))

	counts := make(map[drift.Severity]int)
	for _, s := range report.Signals {
		counts[s.Severity]++
	}

	parts := []string{}
	for _, sev := range []drift.Severity{drift.SeverityCritical, drift.SeverityHigh, drift.SeverityMedium, drift.SeverityLow} {
		if c, ok := counts[sev]; ok && c > 0 {
			parts = append(parts, fmt.Sprintf("%d %s", c, sev))
		}
	}
	_, _ = fmt.Fprintf(out, "(%s)\n", strings.Join(parts, ", "))

	if report.HasHighOrCritical() {
		_, _ = fmt.Fprintln(out, "\nWARNING: High or critical signals detected. Manual review recommended.")
	}
}

func severityMarker(sev drift.Severity) string {
	switch sev {
	case drift.SeverityCritical:
		return "CRIT"
	case drift.SeverityHigh:
		return "HIGH"
	case drift.SeverityMedium:
		return " MED"
	case drift.SeverityLow:
		return " LOW"
	default:
		return "  ? "
	}
}

func loadSkillBOM(path string) (*skillbom.SkillBOM, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading %s: %w", path, err)
	}

	var bom skillbom.SkillBOM
	if err := json.Unmarshal(data, &bom); err != nil {
		return nil, fmt.Errorf("parsing %s: %w", path, err)
	}

	return &bom, nil
}
