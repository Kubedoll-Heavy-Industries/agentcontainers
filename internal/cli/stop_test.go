package cli

import (
	"strings"
	"testing"
)

func TestStopFlagParsing(t *testing.T) {
	tests := []struct {
		name    string
		args    []string
		wantErr string
	}{
		{
			name:    "no args",
			args:    []string{"stop"},
			wantErr: "accepts 1 arg(s), received 0",
		},
		{
			name:    "too many args",
			args:    []string{"stop", "id1", "id2"},
			wantErr: "accepts 1 arg(s), received 2",
		},
		{
			name:    "unknown runtime",
			args:    []string{"stop", "--runtime", "podman", "abc123"},
			wantErr: "unknown runtime",
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

func TestStopForceFlag(t *testing.T) {
	cmd := newStopCmd()
	if err := cmd.ParseFlags([]string{"--force", "abc123"}); err != nil {
		t.Fatalf("unexpected error parsing --force flag: %v", err)
	}

	forceVal, err := cmd.Flags().GetBool("force")
	if err != nil {
		t.Fatalf("unexpected error getting force flag: %v", err)
	}
	if !forceVal {
		t.Error("expected --force to be true")
	}
}

func TestStopRuntimeDefault(t *testing.T) {
	cmd := newStopCmd()
	if err := cmd.ParseFlags([]string{"abc123"}); err != nil {
		t.Fatalf("unexpected error parsing flags: %v", err)
	}

	runtimeVal, err := cmd.Flags().GetString("runtime")
	if err != nil {
		t.Fatalf("unexpected error getting runtime flag: %v", err)
	}
	if runtimeVal != "docker" {
		t.Errorf("expected default runtime %q, got %q", "docker", runtimeVal)
	}
}
