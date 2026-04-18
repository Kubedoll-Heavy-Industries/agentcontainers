package cli

import (
	"bytes"
	"strings"
	"testing"
)

func TestComponentCommandStructure(t *testing.T) {
	cmd := newComponentCmd()

	if cmd.Use != "component" {
		t.Errorf("expected Use %q, got %q", "component", cmd.Use)
	}

	subCmds := cmd.Commands()
	if len(subCmds) != 1 {
		t.Fatalf("expected 1 subcommand, got %d", len(subCmds))
	}

	if subCmds[0].Use != "inspect <oci-reference>" {
		t.Errorf("expected subcommand Use %q, got %q", "inspect <oci-reference>", subCmds[0].Use)
	}
}

func TestComponentInspectRequiresArg(t *testing.T) {
	var outBuf bytes.Buffer
	cmd := newRootCmd("test", "abc", "now")
	cmd.SetOut(&outBuf)
	cmd.SetErr(&outBuf)
	cmd.SetArgs([]string{"component", "inspect"})

	err := cmd.Execute()
	if err == nil {
		t.Fatal("expected error when no OCI reference provided")
	}
}

func TestComponentInspectRejectsExtraArgs(t *testing.T) {
	var outBuf bytes.Buffer
	cmd := newRootCmd("test", "abc", "now")
	cmd.SetOut(&outBuf)
	cmd.SetErr(&outBuf)
	cmd.SetArgs([]string{"component", "inspect", "ghcr.io/foo/bar:latest", "extra-arg"})

	err := cmd.Execute()
	if err == nil {
		t.Fatal("expected error for extra args")
	}
}

func TestComponentInspectOutput(t *testing.T) {
	tests := []struct {
		name    string
		ref     string
		wantOut []string
	}{
		{
			name: "tagged OCI reference",
			ref:  "ghcr.io/microsoft/time-server-js:latest",
			wantOut: []string{
				"Component:  ghcr.io/microsoft/time-server-js:latest",
				"Status:",
				"agentcontainer enforcer start",
			},
		},
		{
			name: "digest-pinned OCI reference",
			ref:  "ghcr.io/mcp-tools/filesystem:1.0@sha256:abc123",
			wantOut: []string{
				"Component:  ghcr.io/mcp-tools/filesystem:1.0@sha256:abc123",
				"agentcontainer enforcer start",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var outBuf bytes.Buffer
			cmd := newRootCmd("test", "abc", "now")
			cmd.SetOut(&outBuf)
			cmd.SetArgs([]string{"component", "inspect", tt.ref})

			err := cmd.Execute()
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			output := outBuf.String()
			for _, want := range tt.wantOut {
				if !strings.Contains(output, want) {
					t.Errorf("output missing %q\nGot:\n%s", want, output)
				}
			}
		})
	}
}

func TestComponentInspectOutputContainsRef(t *testing.T) {
	ref := "ghcr.io/example/tool:v1.2.3"

	var outBuf bytes.Buffer
	cmd := newRootCmd("test", "abc", "now")
	cmd.SetOut(&outBuf)
	cmd.SetArgs([]string{"component", "inspect", ref})

	err := cmd.Execute()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	output := outBuf.String()
	if !strings.Contains(output, ref) {
		t.Errorf("expected output to contain the OCI reference %q\nGot:\n%s", ref, output)
	}
}

func TestComponentHelpText(t *testing.T) {
	var outBuf bytes.Buffer
	cmd := newRootCmd("test", "abc", "now")
	cmd.SetOut(&outBuf)
	cmd.SetArgs([]string{"component", "--help"})

	if err := cmd.Execute(); err != nil {
		t.Fatalf("component --help failed: %v", err)
	}

	output := outBuf.String()
	if !strings.Contains(output, "WASM") {
		t.Errorf("expected 'WASM' in help text, got:\n%s", output)
	}
	if !strings.Contains(output, "inspect") {
		t.Errorf("expected 'inspect' in help text, got:\n%s", output)
	}
}

func TestComponentInspectHelpText(t *testing.T) {
	var outBuf bytes.Buffer
	cmd := newRootCmd("test", "abc", "now")
	cmd.SetOut(&outBuf)
	cmd.SetArgs([]string{"component", "inspect", "--help"})

	if err := cmd.Execute(); err != nil {
		t.Fatalf("component inspect --help failed: %v", err)
	}

	output := outBuf.String()
	if !strings.Contains(output, "oci-reference") {
		t.Errorf("expected 'oci-reference' in help text, got:\n%s", output)
	}
}

func TestComponentRegisteredInRoot(t *testing.T) {
	cmd := newRootCmd("test", "abc", "now")

	var found bool
	for _, sub := range cmd.Commands() {
		if sub.Use == "component" {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected 'component' subcommand to be registered on root command")
	}
}
