package cli

import (
	"strings"
	"testing"
)

func TestLogsFlagParsing(t *testing.T) {
	tests := []struct {
		name    string
		args    []string
		wantErr string
	}{
		{
			name:    "no args",
			args:    []string{"logs"},
			wantErr: "accepts 1 arg(s), received 0",
		},
		{
			name:    "too many args",
			args:    []string{"logs", "id1", "id2"},
			wantErr: "accepts 1 arg(s), received 2",
		},
		{
			name:    "unknown runtime",
			args:    []string{"logs", "--runtime", "podman", "abc123"},
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

func TestLogsFollowShortFlag(t *testing.T) {
	cmd := newLogsCmd()
	if err := cmd.ParseFlags([]string{"-f", "abc123"}); err != nil {
		t.Fatalf("unexpected error parsing -f flag: %v", err)
	}

	followVal, err := cmd.Flags().GetBool("follow")
	if err != nil {
		t.Fatalf("unexpected error getting follow flag: %v", err)
	}
	if !followVal {
		t.Error("expected -f to set follow to true")
	}
}

func TestLogsFollowLongFlag(t *testing.T) {
	cmd := newLogsCmd()
	if err := cmd.ParseFlags([]string{"--follow", "abc123"}); err != nil {
		t.Fatalf("unexpected error parsing --follow flag: %v", err)
	}

	followVal, err := cmd.Flags().GetBool("follow")
	if err != nil {
		t.Fatalf("unexpected error getting follow flag: %v", err)
	}
	if !followVal {
		t.Error("expected --follow to set follow to true")
	}
}

func TestLogsRuntimeDefault(t *testing.T) {
	cmd := newLogsCmd()
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
