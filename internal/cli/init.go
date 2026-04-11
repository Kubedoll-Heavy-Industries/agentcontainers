package cli

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"
)

const agentcontainerFileName = "agentcontainer.json"

func newInitCmd() *cobra.Command {
	var (
		dir   string
		force bool
	)

	cmd := &cobra.Command{
		Use:   "init",
		Short: "Initialize agentcontainer.json from an existing devcontainer",
		Long: `Detect an existing devcontainer.json and generate an agentcontainer.json
with default-deny agent capabilities. If no devcontainer.json is found,
generates a minimal configuration with a default base image.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runInit(cmd, dir, force)
		},
	}

	cmd.Flags().StringVar(&dir, "dir", "", "Workspace directory (defaults to current directory)")
	cmd.Flags().BoolVar(&force, "force", false, "Overwrite existing agentcontainer.json")

	return cmd
}

func runInit(cmd *cobra.Command, dir string, force bool) error {
	// Resolve workspace directory.
	if dir == "" {
		cwd, err := os.Getwd()
		if err != nil {
			return fmt.Errorf("unable to determine working directory: %w", err)
		}
		dir = cwd
	}

	absDir, err := filepath.Abs(dir)
	if err != nil {
		return fmt.Errorf("unable to resolve directory: %w", err)
	}

	outPath := filepath.Join(absDir, agentcontainerFileName)

	// Check if agentcontainer.json already exists.
	if _, err := os.Stat(outPath); err == nil && !force {
		return fmt.Errorf("%s already exists — edit it directly or re-run with --force to overwrite", agentcontainerFileName)
	}

	// Detect an existing devcontainer.json.
	det, err := findDevcontainer(absDir)
	if err != nil {
		return fmt.Errorf("error reading devcontainer.json: %w", err)
	}

	// Build template parameters from detected config (or defaults).
	params := templateParams{}

	if det != nil {
		params.Name = det.Name
		params.Image = det.Image

		if det.Build != nil {
			params.BuildSection = buildSectionFromDetected(det.Build)
		}

		// Note compose files.
		allCompose := det.ComposeFilesFound
		if len(det.DockerComposeFile) > 0 {
			// Include explicitly referenced compose files too.
			for _, cf := range det.DockerComposeFile {
				abs := filepath.Join(absDir, cf)
				if _, err := os.Stat(abs); err == nil {
					// Only add if not already present.
					found := false
					for _, existing := range allCompose {
						if existing == abs {
							found = true
							break
						}
					}
					if !found {
						allCompose = append(allCompose, abs)
					}
				}
			}
		}
		params.DockerComposeComment = composeComment(allCompose)

		if !quiet {
			_, _ = fmt.Fprintf(cmd.OutOrStdout(), "Detected devcontainer.json at %s\n", det.Path)
		}
	} else {
		// Even without a devcontainer.json, check for compose files in the
		// workspace so we can note them in the generated config.
		composeFiles := detectComposeFiles(absDir)
		params.DockerComposeComment = composeComment(composeFiles)

		if !quiet {
			_, _ = fmt.Fprintf(cmd.OutOrStdout(), "No devcontainer.json found — using defaults\n")
		}
	}

	// Render and write the file.
	content := renderTemplate(params)

	if err := os.WriteFile(outPath, []byte(content), 0644); err != nil {
		return fmt.Errorf("unable to write %s: %w", agentcontainerFileName, err)
	}

	if !quiet {
		_, _ = fmt.Fprintf(cmd.OutOrStdout(), "Created %s\n", outPath)
	}

	return nil
}
