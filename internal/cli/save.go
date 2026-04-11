package cli

import (
	"encoding/json"
	"fmt"
	"io"
	"os"

	"github.com/spf13/cobra"

	"github.com/Kubedoll-Heavy-Industries/agentcontainers/internal/config"
)

func newSaveCmd() *cobra.Command {
	var (
		dryRun     bool
		configPath string
	)

	cmd := &cobra.Command{
		Use:   "save [capabilities-file]",
		Short: "Persist approved capabilities to agentcontainer.json",
		Long: `Write approved capability changes back to agentcontainer.json,
preserving existing comments and formatting.

The new capabilities are read from a JSON file argument or from stdin.
Use --dry-run to preview the changes without writing.`,
		Args: cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runSave(cmd, args, dryRun, configPath)
		},
	}

	cmd.Flags().BoolVar(&dryRun, "dry-run", false, "Show changes without writing")
	cmd.Flags().StringVar(&configPath, "config", "", "Path to agentcontainer.json (auto-detected if omitted)")

	return cmd
}

func runSave(cmd *cobra.Command, args []string, dryRun bool, configPath string) error {
	out := cmd.OutOrStdout()

	// 1. Resolve the config file path.
	if configPath == "" {
		cwd, err := os.Getwd()
		if err != nil {
			return fmt.Errorf("save: %w", err)
		}
		_, resolved, err := config.Load(cwd)
		if err != nil {
			return fmt.Errorf("save: %w", err)
		}
		configPath = resolved
	}

	// 2. Read the pending capability changes from file arg or stdin.
	capsData, err := readCapsInput(args, cmd.InOrStdin())
	if err != nil {
		return fmt.Errorf("save: %w", err)
	}

	var newCaps config.Capabilities
	if err := json.Unmarshal(capsData, &newCaps); err != nil {
		return fmt.Errorf("save: parsing capabilities JSON: %w", err)
	}

	// 3. Load current config to show diff.
	currentCfg, err := config.ParseFile(configPath)
	if err != nil {
		return fmt.Errorf("save: loading current config: %w", err)
	}

	// 4. Show diff of changes.
	diff := diffCapabilities(currentCfg.Agent, &newCaps)
	if diff == "" {
		_, _ = fmt.Fprintln(out, "No capability changes to save.")
		return nil
	}

	_, _ = fmt.Fprintln(out, "Capability changes:")
	_, _ = fmt.Fprintln(out, diff)

	// 5. If --dry-run, stop here.
	if dryRun {
		_, _ = fmt.Fprintln(out, "[dry run] no changes written")
		return nil
	}

	// 6. Write the changes, preserving JSONC comments.
	if err := config.SaveCapabilities(configPath, &newCaps); err != nil {
		return err
	}

	_, _ = fmt.Fprintf(out, "Saved capabilities to %s\n", configPath)
	return nil
}

// readCapsInput reads capabilities JSON from the first positional argument
// (a file path) or from stdin if no argument is provided.
func readCapsInput(args []string, stdin io.Reader) ([]byte, error) {
	if len(args) > 0 {
		data, err := os.ReadFile(args[0])
		if err != nil {
			return nil, fmt.Errorf("reading capabilities file: %w", err)
		}
		return data, nil
	}

	data, err := io.ReadAll(stdin)
	if err != nil {
		return nil, fmt.Errorf("reading capabilities from stdin: %w", err)
	}
	if len(data) == 0 {
		return nil, fmt.Errorf("no capabilities provided (pass a file argument or pipe JSON to stdin)")
	}
	return data, nil
}

// diffCapabilities produces a human-readable summary of what changed
// between the current agent config and the new capabilities.
func diffCapabilities(current *config.AgentConfig, newCaps *config.Capabilities) string {
	var oldCaps *config.Capabilities
	if current != nil {
		oldCaps = current.Capabilities
	}

	oldJSON, _ := json.MarshalIndent(oldCaps, "", "  ")
	newJSON, _ := json.MarshalIndent(newCaps, "", "  ")

	oldStr := string(oldJSON)
	newStr := string(newJSON)

	if oldStr == newStr {
		return ""
	}

	return fmt.Sprintf("--- current capabilities\n%s\n\n+++ new capabilities\n%s", oldStr, newStr)
}
