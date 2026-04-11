package cli

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func TestPsFlagParsing(t *testing.T) {
	tests := []struct {
		name    string
		args    []string
		wantErr string
	}{
		{
			name:    "extra args rejected",
			args:    []string{"ps", "unexpected"},
			wantErr: "unknown command",
		},
		{
			name:    "unknown runtime",
			args:    []string{"ps", "--runtime", "podman"},
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

func TestPsDefaultFlags(t *testing.T) {
	cmd := newPsCmd()
	if err := cmd.ParseFlags([]string{}); err != nil {
		t.Fatalf("unexpected error parsing flags: %v", err)
	}

	runtimeVal, err := cmd.Flags().GetString("runtime")
	if err != nil {
		t.Fatalf("unexpected error getting runtime flag: %v", err)
	}
	if runtimeVal != "docker" {
		t.Errorf("expected default runtime %q, got %q", "docker", runtimeVal)
	}

	allVal, err := cmd.Flags().GetBool("all")
	if err != nil {
		t.Fatalf("unexpected error getting all flag: %v", err)
	}
	if allVal {
		t.Error("expected --all to default to false")
	}

	jsonVal, err := cmd.Flags().GetBool("json")
	if err != nil {
		t.Fatalf("unexpected error getting json flag: %v", err)
	}
	if jsonVal {
		t.Error("expected --json to default to false")
	}
}

func TestShortID(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"abc123def456789", "abc123def456"},
		{"short", "short"},
		{"exactly12ch", "exactly12ch"},
		{"", ""},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got := shortID(tt.input)
			if got != tt.want {
				t.Errorf("shortID(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

func TestRelativeTime(t *testing.T) {
	now := time.Now()

	tests := []struct {
		name string
		t    time.Time
		want string
	}{
		{"just now", now.Add(-30 * time.Second), "just now"},
		{"1 minute ago", now.Add(-90 * time.Second), "1 minute ago"},
		{"5 minutes ago", now.Add(-5 * time.Minute), "5 minutes ago"},
		{"1 hour ago", now.Add(-90 * time.Minute), "1 hour ago"},
		{"3 hours ago", now.Add(-3 * time.Hour), "3 hours ago"},
		{"1 day ago", now.Add(-36 * time.Hour), "1 day ago"},
		{"5 days ago", now.Add(-5 * 24 * time.Hour), "5 days ago"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := relativeTime(tt.t)
			if got != tt.want {
				t.Errorf("relativeTime() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestPsEntryJSON(t *testing.T) {
	entry := psEntry{
		ContainerID: "abc123def456",
		Name:        "my-agent",
		Image:       "ubuntu:22.04",
		Status:      "running",
		Created:     "2026-02-13T10:00:00Z",
	}

	data, err := json.Marshal(entry)
	if err != nil {
		t.Fatalf("unexpected marshal error: %v", err)
	}

	var decoded psEntry
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("unexpected unmarshal error: %v", err)
	}

	if decoded.ContainerID != entry.ContainerID {
		t.Errorf("ContainerID = %q, want %q", decoded.ContainerID, entry.ContainerID)
	}
	if decoded.Name != entry.Name {
		t.Errorf("Name = %q, want %q", decoded.Name, entry.Name)
	}
	if decoded.Image != entry.Image {
		t.Errorf("Image = %q, want %q", decoded.Image, entry.Image)
	}
	if decoded.Status != entry.Status {
		t.Errorf("Status = %q, want %q", decoded.Status, entry.Status)
	}
}
