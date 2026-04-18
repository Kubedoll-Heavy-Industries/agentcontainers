package cli

import (
	"fmt"

	"github.com/spf13/cobra"
)

func newComponentCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "component",
		Short: "Manage WASM Component tools",
		Long: `Manage WebAssembly Component tools for agent sessions.
WASM Components start in <5ms, consume ~5 MiB, and run in a
WASI sandbox with deny-by-default capability enforcement.`,
	}

	cmd.AddCommand(
		newComponentInspectCmd(),
	)

	return cmd
}

func newComponentInspectCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "inspect <oci-reference>",
		Short: "Inspect tools exported by a WASM Component",
		Long: `Fetch a WASM Component from an OCI registry and list the tools
it exports. This is a read-only operation — the component is not
loaded into any running session.

Full WIT introspection requires a running ac-enforcer sidecar with
Wassette support (Phase B). In Phase A, this command validates the
OCI reference and reports that introspection is not yet available.`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runComponentInspect(cmd, args[0])
		},
	}

	return cmd
}

func runComponentInspect(cmd *cobra.Command, ref string) error {
	out := cmd.OutOrStdout()

	if ref == "" {
		return fmt.Errorf("component inspect: OCI reference is required")
	}

	_, _ = fmt.Fprintf(out, "Component:  %s\n", ref)
	_, _ = fmt.Fprintf(out, "Status:     WIT introspection requires a running ac-enforcer with Wassette support\n")
	_, _ = fmt.Fprintf(out, "            Start the enforcer with: agentcontainer enforcer start\n")
	_, _ = fmt.Fprintf(out, "            Then re-run: agentcontainer component inspect %s\n", ref)

	return nil
}
