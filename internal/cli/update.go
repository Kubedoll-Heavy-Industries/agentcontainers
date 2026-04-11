package cli

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"
	"github.com/tailscale/hujson"

	"github.com/Kubedoll-Heavy-Industries/agentcontainers/internal/config"
)

// devcontainerFields lists the devcontainer-compatible fields that ac update
// should sync from devcontainer.json into agentcontainer.json. The "agent"
// key is intentionally excluded — it is agent-specific configuration that
// must never be overwritten by a devcontainer merge. If devcontainer.json
// happens to contain an "agent" key, it is silently ignored.
var devcontainerFields = []string{
	"name",
	"image",
	"build",
	"features",
	"mounts",
	"forwardPorts",
	"remoteUser",
	"containerEnv",
	"remoteEnv",
	"postCreateCommand",
	"postStartCommand",
	"postAttachCommand",
}

func newUpdateCmd() *cobra.Command {
	var (
		dryRun     bool
		configPath string
	)

	cmd := &cobra.Command{
		Use:   "update",
		Short: "Merge devcontainer.json changes into agentcontainer.json",
		Long: `Compare the current devcontainer.json against the agentcontainer.json
and merge any changed devcontainer-compatible fields. The agent-specific
configuration (the "agent" key) is never modified.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runUpdate(cmd, dryRun, configPath)
		},
	}

	cmd.Flags().BoolVar(&dryRun, "dry-run", false, "Print the diff but do not write changes")
	cmd.Flags().StringVarP(&configPath, "config", "c", "", "Path to agentcontainer.json")

	return cmd
}

func runUpdate(cmd *cobra.Command, dryRun bool, configPath string) error {
	// 1. Locate the agentcontainer.json.
	acPath, err := resolveAgentcontainerPath(configPath)
	if err != nil {
		return err
	}

	// 2. Locate the corresponding devcontainer.json.
	dcPath, err := findDevcontainerForUpdate(acPath)
	if err != nil {
		return err
	}

	// 3. Read and parse both files as raw JSON objects.
	acData, err := os.ReadFile(acPath)
	if err != nil {
		return exitError{code: 3, err: fmt.Errorf("update: reading agentcontainer.json: %w", err)}
	}

	dcData, err := os.ReadFile(dcPath)
	if err != nil {
		return exitError{code: 3, err: fmt.Errorf("update: reading devcontainer.json: %w", err)}
	}

	// Standardize JSONC to plain JSON for comparison.
	acJSON, err := hujson.Standardize(acData)
	if err != nil {
		return exitError{code: 2, err: fmt.Errorf("update: parsing agentcontainer.json: %w", err)}
	}
	dcJSON, err := hujson.Standardize(dcData)
	if err != nil {
		return exitError{code: 2, err: fmt.Errorf("update: parsing devcontainer.json: %w", err)}
	}

	var acMap map[string]json.RawMessage
	if err := json.Unmarshal(acJSON, &acMap); err != nil {
		return exitError{code: 2, err: fmt.Errorf("update: parsing agentcontainer.json: %w", err)}
	}

	var dcMap map[string]json.RawMessage
	if err := json.Unmarshal(dcJSON, &dcMap); err != nil {
		return exitError{code: 2, err: fmt.Errorf("update: parsing devcontainer.json: %w", err)}
	}

	// 4. Compute changes for devcontainer-compatible fields.
	changes := computeChanges(acMap, dcMap)
	if len(changes) == 0 {
		_, _ = fmt.Fprintln(cmd.OutOrStdout(), "No changes detected")
		return nil
	}

	// 5. Display the diff.
	out := cmd.OutOrStdout()
	_, _ = fmt.Fprintf(out, "Changes from %s:\n", filepath.Base(dcPath))
	for _, c := range changes {
		_, _ = fmt.Fprintf(out, "  %s\n", c)
	}

	// 6. If dry-run, stop here.
	if dryRun {
		return nil
	}

	// 7. Prompt for confirmation.
	_, _ = fmt.Fprint(out, "\nApply these changes? [y/N] ")
	confirmed, err := promptConfirm(cmd)
	if err != nil {
		return exitError{code: 3, err: fmt.Errorf("update: reading confirmation: %w", err)}
	}
	if !confirmed {
		_, _ = fmt.Fprintln(out, "Update cancelled")
		return nil
	}

	// 8. Apply changes and write back.
	merged, err := applyChanges(acData, dcMap)
	if err != nil {
		return exitError{code: 3, err: fmt.Errorf("update: merging changes: %w", err)}
	}

	// 9. Validate the result before writing.
	validationData, err := hujson.Standardize(merged)
	if err != nil {
		return exitError{code: 2, err: fmt.Errorf("update: merged result is invalid JSONC: %w", err)}
	}
	var resultCfg config.AgentContainer
	if err := json.Unmarshal(validationData, &resultCfg); err != nil {
		return exitError{code: 2, err: fmt.Errorf("update: merged result fails schema validation: %w", err)}
	}

	if err := os.WriteFile(acPath, merged, 0644); err != nil {
		return exitError{code: 3, err: fmt.Errorf("update: writing agentcontainer.json: %w", err)}
	}

	_, _ = fmt.Fprintf(out, "Updated %s\n", acPath)
	return nil
}

// resolveAgentcontainerPath finds the agentcontainer.json file, either from
// an explicit --config path or by searching the working directory.
func resolveAgentcontainerPath(configPath string) (string, error) {
	if configPath != "" {
		abs, err := filepath.Abs(configPath)
		if err != nil {
			return "", exitError{code: 3, err: fmt.Errorf("update: resolving config path: %w", err)}
		}
		if _, err := os.Stat(abs); err != nil {
			return "", exitError{code: 3, err: fmt.Errorf("update: config not found: %s", abs)}
		}
		return abs, nil
	}

	cwd, err := os.Getwd()
	if err != nil {
		return "", exitError{code: 3, err: fmt.Errorf("update: determining working directory: %w", err)}
	}

	// Search for agentcontainer.json in the standard locations.
	searchPaths := []string{
		"agentcontainer.json",
		".devcontainer/agentcontainer.json",
	}
	for _, rel := range searchPaths {
		abs := filepath.Join(cwd, rel)
		if _, err := os.Stat(abs); err == nil {
			return abs, nil
		}
	}

	return "", exitError{code: 1, err: fmt.Errorf("update: no agentcontainer.json found")}
}

// findDevcontainerForUpdate locates the devcontainer.json that corresponds
// to the given agentcontainer.json path.
func findDevcontainerForUpdate(acPath string) (string, error) {
	acDir := filepath.Dir(acPath)

	// Search order:
	// 1. Same directory as agentcontainer.json
	// 2. .devcontainer/devcontainer.json relative to workspace root
	// 3. devcontainer.json at workspace root
	candidates := []string{
		filepath.Join(acDir, "devcontainer.json"),
	}

	// If acPath is inside .devcontainer/, also look at the parent directory.
	if filepath.Base(acDir) == ".devcontainer" {
		parentDir := filepath.Dir(acDir)
		candidates = append(candidates,
			filepath.Join(parentDir, ".devcontainer", "devcontainer.json"),
			filepath.Join(parentDir, "devcontainer.json"),
		)
	} else {
		// acPath is at workspace root; look in .devcontainer/ too.
		candidates = append(candidates,
			filepath.Join(acDir, ".devcontainer", "devcontainer.json"),
		)
	}

	for _, path := range candidates {
		if _, err := os.Stat(path); err == nil {
			return path, nil
		}
	}

	return "", exitError{code: 1, err: fmt.Errorf("update: no devcontainer.json found")}
}

// change represents a single field change for display.
type change struct {
	field      string
	oldVal     string
	newVal     string
	changeType string // "added", "changed", "removed"
}

func (c change) String() string {
	switch c.changeType {
	case "added":
		return fmt.Sprintf("%s: (none) -> %s", c.field, c.newVal)
	case "removed":
		return fmt.Sprintf("%s: %s -> (removed)", c.field, c.oldVal)
	default:
		return fmt.Sprintf("%s: %s -> %s", c.field, c.oldVal, c.newVal)
	}
}

// computeChanges compares devcontainer-compatible fields between the
// agentcontainer and devcontainer JSON maps.
func computeChanges(acMap, dcMap map[string]json.RawMessage) []change {
	var changes []change

	for _, field := range devcontainerFields {
		acVal, acHas := acMap[field]
		dcVal, dcHas := dcMap[field]

		if !acHas && !dcHas {
			continue
		}

		if !acHas && dcHas {
			changes = append(changes, change{
				field:      field,
				newVal:     summarizeJSON(dcVal),
				changeType: "added",
			})
			continue
		}

		if acHas && !dcHas {
			changes = append(changes, change{
				field:      field,
				oldVal:     summarizeJSON(acVal),
				changeType: "removed",
			})
			continue
		}

		// Both present — compare.
		if !jsonEqual(acVal, dcVal) {
			changes = append(changes, change{
				field:      field,
				oldVal:     summarizeJSON(acVal),
				newVal:     summarizeJSON(dcVal),
				changeType: "changed",
			})
		}
	}

	return changes
}

// jsonEqual compares two json.RawMessage values for semantic equality.
func jsonEqual(a, b json.RawMessage) bool {
	var va, vb any
	if err := json.Unmarshal(a, &va); err != nil {
		return false
	}
	if err := json.Unmarshal(b, &vb); err != nil {
		return false
	}

	// Re-marshal to canonical form for comparison.
	ca, _ := json.Marshal(va)
	cb, _ := json.Marshal(vb)
	return string(ca) == string(cb)
}

// summarizeJSON produces a compact string representation of a JSON value
// for display in the diff output.
func summarizeJSON(data json.RawMessage) string {
	s := strings.TrimSpace(string(data))
	// For simple scalar values, remove quotes for readability.
	var str string
	if err := json.Unmarshal(data, &str); err == nil {
		return str
	}
	if len(s) > 60 {
		return s[:57] + "..."
	}
	return s
}

// applyChanges merges devcontainer fields from dcMap into the agentcontainer
// JSONC data, preserving comments and formatting as much as possible.
func applyChanges(acData []byte, dcMap map[string]json.RawMessage) ([]byte, error) {
	// Parse the agentcontainer.json as a hujson Value to preserve comments.
	val, err := hujson.Parse(acData)
	if err != nil {
		return nil, fmt.Errorf("parsing agentcontainer JSONC: %w", err)
	}

	// Standardize to get a clean JSON map we can manipulate.
	acJSON, err := hujson.Standardize(append([]byte(nil), acData...))
	if err != nil {
		return nil, fmt.Errorf("standardizing agentcontainer JSONC: %w", err)
	}

	var acMap map[string]json.RawMessage
	if err := json.Unmarshal(acJSON, &acMap); err != nil {
		return nil, fmt.Errorf("unmarshaling agentcontainer: %w", err)
	}

	// Apply devcontainer field changes.
	for _, field := range devcontainerFields {
		dcVal, dcHas := dcMap[field]
		_, acHas := acMap[field]

		if dcHas {
			acMap[field] = dcVal
		} else if acHas {
			// Field was removed from devcontainer.json — remove from
			// agentcontainer.json too, but only for devcontainer fields.
			delete(acMap, field)
		}
	}

	// Re-serialize the merged map.
	//
	// Known limitation (M0): JSONC comments are NOT preserved after update.
	// A structural merge produces clean JSON output. The agent key and its
	// values are preserved since we only touch devcontainer fields, but any
	// inline comments in the original file will be lost. Full comment
	// preservation via hujson AST patching is planned for M1.
	_ = val // hujson AST available for future comment-preserving merge
	result, err := json.MarshalIndent(acMap, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("marshaling merged config: %w", err)
	}

	result = append(result, '\n')
	return result, nil
}

// promptConfirm reads a y/N response from stdin.
func promptConfirm(cmd *cobra.Command) (bool, error) {
	in := cmd.InOrStdin()
	scanner := bufio.NewScanner(in)
	if !scanner.Scan() {
		if err := scanner.Err(); err != nil {
			return false, err
		}
		return false, nil
	}
	answer := strings.TrimSpace(strings.ToLower(scanner.Text()))
	return answer == "y" || answer == "yes", nil
}

// exitError wraps an error with an exit code.
type exitError struct {
	code int
	err  error
}

func (e exitError) Error() string {
	return e.err.Error()
}

func (e exitError) Unwrap() error {
	return e.err
}
