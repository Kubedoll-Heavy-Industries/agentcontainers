package cli

import (
	"strings"
	"testing"
)

func TestSbomFlagParsing(t *testing.T) {
	tests := []struct {
		name    string
		args    []string
		wantErr string
	}{
		{
			name:    "no args",
			args:    []string{"sbom"},
			wantErr: "accepts 1 arg(s), received 0",
		},
		{
			name:    "too many args",
			args:    []string{"sbom", "img1", "img2"},
			wantErr: "accepts 1 arg(s), received 2",
		},
		{
			name:    "unknown tool",
			args:    []string{"sbom", "--tool", "unknown", "alpine:3.19"},
			wantErr: "unknown tool",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cmd := newRootCmd("test", "abc", "now")
			cmd.SetArgs(tt.args)

			err := cmd.Execute()
			if err == nil {
				t.Fatalf("expected error containing %q", tt.wantErr)
			}
			if !strings.Contains(err.Error(), tt.wantErr) {
				t.Errorf("expected error containing %q, got: %v", tt.wantErr, err)
			}
		})
	}
}

func TestSbomDefaultFlags(t *testing.T) {
	cmd := newSbomCmd()
	if err := cmd.ParseFlags([]string{}); err != nil {
		t.Fatalf("unexpected error parsing flags: %v", err)
	}

	toolVal, err := cmd.Flags().GetString("tool")
	if err != nil {
		t.Fatalf("unexpected error getting tool flag: %v", err)
	}
	if toolVal != "syft" {
		t.Errorf("expected default tool %q, got %q", "syft", toolVal)
	}

	outputVal, err := cmd.Flags().GetString("output")
	if err != nil {
		t.Fatalf("unexpected error getting output flag: %v", err)
	}
	if outputVal != "" {
		t.Errorf("expected default output %q, got %q", "", outputVal)
	}
}

func TestSbomToolNotInstalled(t *testing.T) {
	// Both syft and cdxgen are unlikely to be in PATH during unit tests.
	// The command should return a clear "not installed" error.
	cmd := newRootCmd("test", "abc", "now")
	cmd.SetArgs([]string{"sbom", "--tool", "syft", "alpine:3.19"})

	err := cmd.Execute()
	if err == nil {
		t.Skip("syft is installed; cannot test missing-tool path")
	}
	if !strings.Contains(err.Error(), "not installed") && !strings.Contains(err.Error(), "not in PATH") {
		t.Errorf("expected 'not installed' error, got: %v", err)
	}
}
