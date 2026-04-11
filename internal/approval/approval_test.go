package approval

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Kubedoll-Heavy-Industries/agentcontainers/internal/config"
)

func TestResponse_String(t *testing.T) {
	tests := []struct {
		resp Response
		want string
	}{
		{Deny, "deny"},
		{AllowOnce, "allow-once"},
		{AllowSession, "allow-session"},
		{AllowPersist, "allow-persist"},
		{Response(99), "unknown"},
	}

	for _, tt := range tests {
		t.Run(tt.want, func(t *testing.T) {
			if got := tt.resp.String(); got != tt.want {
				t.Errorf("Response(%d).String() = %q, want %q", tt.resp, got, tt.want)
			}
		})
	}
}

func TestTerminalApprover_Prompt_Deny(t *testing.T) {
	in := strings.NewReader("d\n")
	out := &bytes.Buffer{}

	approver := NewTerminalApprover(WithInput(in), WithOutput(out))
	req := Request{
		Category: "filesystem",
		Action:   "read /home/user/project/**",
		Details:  "Agent needs to read project files",
	}

	resp, err := approver.Prompt(req)
	if err != nil {
		t.Fatalf("Prompt() error: %v", err)
	}
	if resp != Deny {
		t.Errorf("Prompt() = %v, want %v", resp, Deny)
	}

	// Verify output contains expected elements.
	output := out.String()
	if !strings.Contains(output, "Capability Request") {
		t.Error("output should contain 'Capability Request'")
	}
	if !strings.Contains(output, "filesystem") {
		t.Error("output should contain the category")
	}
	if !strings.Contains(output, "read /home/user/project/**") {
		t.Error("output should contain the action")
	}
}

func TestTerminalApprover_Prompt_AllowOnce(t *testing.T) {
	in := strings.NewReader("o\n")
	out := &bytes.Buffer{}

	approver := NewTerminalApprover(WithInput(in), WithOutput(out))
	req := Request{Category: "network", Action: "connect to api.example.com:443"}

	resp, err := approver.Prompt(req)
	if err != nil {
		t.Fatalf("Prompt() error: %v", err)
	}
	if resp != AllowOnce {
		t.Errorf("Prompt() = %v, want %v", resp, AllowOnce)
	}
}

func TestTerminalApprover_Prompt_AllowSession(t *testing.T) {
	in := strings.NewReader("s\n")
	out := &bytes.Buffer{}

	approver := NewTerminalApprover(WithInput(in), WithOutput(out))
	req := Request{Category: "shell", Action: "execute npm install"}

	resp, err := approver.Prompt(req)
	if err != nil {
		t.Fatalf("Prompt() error: %v", err)
	}
	if resp != AllowSession {
		t.Errorf("Prompt() = %v, want %v", resp, AllowSession)
	}
}

func TestTerminalApprover_Prompt_AllowPersist(t *testing.T) {
	in := strings.NewReader("p\n")
	out := &bytes.Buffer{}

	approver := NewTerminalApprover(WithInput(in), WithOutput(out))
	req := Request{Category: "git", Action: "push to feature/*"}

	resp, err := approver.Prompt(req)
	if err != nil {
		t.Fatalf("Prompt() error: %v", err)
	}
	if resp != AllowPersist {
		t.Errorf("Prompt() = %v, want %v", resp, AllowPersist)
	}
}

func TestTerminalApprover_Prompt_LongForm(t *testing.T) {
	tests := []struct {
		input string
		want  Response
	}{
		{"deny\n", Deny},
		{"once\n", AllowOnce},
		{"session\n", AllowSession},
		{"persist\n", AllowPersist},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			in := strings.NewReader(tt.input)
			out := &bytes.Buffer{}

			approver := NewTerminalApprover(WithInput(in), WithOutput(out))
			req := Request{Category: "filesystem", Action: "test"}

			resp, err := approver.Prompt(req)
			if err != nil {
				t.Fatalf("Prompt() error: %v", err)
			}
			if resp != tt.want {
				t.Errorf("Prompt() = %v, want %v", resp, tt.want)
			}
		})
	}
}

func TestTerminalApprover_Prompt_InvalidThenValid(t *testing.T) {
	// User enters invalid input, then valid input.
	in := strings.NewReader("x\ninvalid\no\n")
	out := &bytes.Buffer{}

	approver := NewTerminalApprover(WithInput(in), WithOutput(out))
	req := Request{Category: "shell", Action: "test"}

	resp, err := approver.Prompt(req)
	if err != nil {
		t.Fatalf("Prompt() error: %v", err)
	}
	if resp != AllowOnce {
		t.Errorf("Prompt() = %v, want %v", resp, AllowOnce)
	}

	// Verify error messages were shown.
	output := out.String()
	if !strings.Contains(output, "Invalid choice") {
		t.Error("output should contain 'Invalid choice' for bad input")
	}
}

func TestTerminalApprover_Prompt_EOF(t *testing.T) {
	// Empty input (EOF immediately).
	in := strings.NewReader("")
	out := &bytes.Buffer{}

	approver := NewTerminalApprover(WithInput(in), WithOutput(out))
	req := Request{Category: "filesystem", Action: "test"}

	resp, err := approver.Prompt(req)
	if err != nil {
		t.Fatalf("Prompt() error: %v", err)
	}
	if resp != Deny {
		t.Errorf("Prompt() on EOF = %v, want %v", resp, Deny)
	}
}

func TestTerminalApprover_NonInteractive(t *testing.T) {
	out := &bytes.Buffer{}

	approver := NewTerminalApprover(
		WithNonInteractive(true),
		WithOutput(out),
	)

	req := Request{
		Category: "filesystem",
		Action:   "read /etc/passwd",
	}

	resp, err := approver.Prompt(req)
	if err != nil {
		t.Fatalf("Prompt() error: %v", err)
	}
	if resp != Deny {
		t.Errorf("Prompt() in non-interactive mode = %v, want %v", resp, Deny)
	}

	output := out.String()
	if !strings.Contains(output, "auto-denied") {
		t.Error("output should indicate auto-denial in non-interactive mode")
	}
	if !strings.Contains(output, "non-interactive") {
		t.Error("output should mention non-interactive mode")
	}
}

func TestTerminalApprover_CaseInsensitive(t *testing.T) {
	tests := []struct {
		input string
		want  Response
	}{
		{"D\n", Deny},
		{"O\n", AllowOnce},
		{"S\n", AllowSession},
		{"P\n", AllowPersist},
		{"DENY\n", Deny},
		{"PERSIST\n", AllowPersist},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			in := strings.NewReader(tt.input)
			out := &bytes.Buffer{}

			approver := NewTerminalApprover(WithInput(in), WithOutput(out))
			req := Request{Category: "test", Action: "test"}

			resp, err := approver.Prompt(req)
			if err != nil {
				t.Fatalf("Prompt() error: %v", err)
			}
			if resp != tt.want {
				t.Errorf("Prompt(%q) = %v, want %v", tt.input, resp, tt.want)
			}
		})
	}
}

func TestManager_Check_PreApproved(t *testing.T) {
	// Create a baseline with filesystem read capability.
	baseline := &config.Capabilities{
		Filesystem: &config.FilesystemCaps{
			Read: []string{"/workspace/**"},
		},
	}

	out := &bytes.Buffer{}
	approver := NewTerminalApprover(WithOutput(out))

	mgr := NewManager(approver, "/dev/null", baseline)

	req := Request{
		Category: "filesystem",
		Action:   "read /workspace/src/main.go",
		Capability: &config.FilesystemCaps{
			Read: []string{"/workspace/src/main.go"},
		},
	}

	approved, err := mgr.Check(req)
	if err != nil {
		t.Fatalf("Check() error: %v", err)
	}
	if !approved {
		t.Error("Check() = false, want true for pre-approved capability")
	}

	// Verify no prompt was shown.
	if strings.Contains(out.String(), "Capability Request") {
		t.Error("should not prompt for pre-approved capability")
	}
}

func TestManager_Check_NewCapability_Deny(t *testing.T) {
	in := strings.NewReader("d\n")
	out := &bytes.Buffer{}

	approver := NewTerminalApprover(WithInput(in), WithOutput(out))
	mgr := NewManager(approver, "/dev/null", nil)

	req := Request{
		Category: "network",
		Action:   "connect to evil.com:443",
		Capability: &config.NetworkCaps{
			Egress: []config.EgressRule{{Host: "evil.com", Port: 443}},
		},
	}

	approved, err := mgr.Check(req)
	if err != nil {
		t.Fatalf("Check() error: %v", err)
	}
	if approved {
		t.Error("Check() = true, want false for denied capability")
	}

	// Verify prompt was shown.
	if !strings.Contains(out.String(), "Capability Request") {
		t.Error("should prompt for new capability")
	}
}

func TestManager_Check_NewCapability_AllowOnce(t *testing.T) {
	// First prompt: allow once.
	in1 := strings.NewReader("o\n")
	out1 := &bytes.Buffer{}

	approver1 := NewTerminalApprover(WithInput(in1), WithOutput(out1))
	mgr := NewManager(approver1, "/dev/null", nil)

	req := Request{
		Category: "shell",
		Action:   "execute npm install",
		Capability: &config.ShellCaps{
			Commands: []config.ShellCommand{{Binary: "npm"}},
		},
	}

	approved, err := mgr.Check(req)
	if err != nil {
		t.Fatalf("Check() error: %v", err)
	}
	if !approved {
		t.Error("Check() = false, want true for allow-once")
	}

	// Second check should still prompt (allow-once doesn't persist in session).
	in2 := strings.NewReader("d\n")
	out2 := &bytes.Buffer{}

	approver2 := NewTerminalApprover(WithInput(in2), WithOutput(out2))
	mgr.approver = approver2

	approved2, err := mgr.Check(req)
	if err != nil {
		t.Fatalf("Check() error: %v", err)
	}
	if approved2 {
		t.Error("Second Check() should deny after allow-once")
	}
}

func TestManager_Check_NewCapability_AllowSession(t *testing.T) {
	// First prompt: allow session.
	in := strings.NewReader("s\n")
	out := &bytes.Buffer{}

	approver := NewTerminalApprover(WithInput(in), WithOutput(out))
	mgr := NewManager(approver, "/dev/null", nil)

	req := Request{
		Category: "shell",
		Action:   "execute npm install",
		Capability: &config.ShellCaps{
			Commands: []config.ShellCommand{{Binary: "npm"}},
		},
	}

	approved, err := mgr.Check(req)
	if err != nil {
		t.Fatalf("Check() error: %v", err)
	}
	if !approved {
		t.Error("Check() = false, want true for allow-session")
	}

	// Second check should not prompt (session approval persists).
	out2 := &bytes.Buffer{}
	mgr.approver = NewTerminalApprover(WithOutput(out2))

	approved2, err := mgr.Check(req)
	if err != nil {
		t.Fatalf("Second Check() error: %v", err)
	}
	if !approved2 {
		t.Error("Second Check() = false, should be auto-approved from session")
	}

	// Verify no prompt was shown on second check.
	if strings.Contains(out2.String(), "Capability Request") {
		t.Error("should not prompt for session-approved capability")
	}
}

func TestManager_SessionCapabilities(t *testing.T) {
	baseline := &config.Capabilities{
		Filesystem: &config.FilesystemCaps{
			Read: []string{"/workspace/**"},
		},
	}

	in := strings.NewReader("s\n")
	out := &bytes.Buffer{}

	approver := NewTerminalApprover(WithInput(in), WithOutput(out))
	mgr := NewManager(approver, "/dev/null", baseline)

	// Approve a new network capability.
	req := Request{
		Category: "network",
		Action:   "connect to api.github.com",
		Capability: &config.NetworkCaps{
			Egress: []config.EgressRule{{Host: "api.github.com", Port: 443}},
		},
	}

	_, err := mgr.Check(req)
	if err != nil {
		t.Fatalf("Check() error: %v", err)
	}

	// Get combined capabilities.
	combined := mgr.SessionCapabilities()

	// Should have both baseline filesystem and session network.
	if combined.Filesystem == nil || len(combined.Filesystem.Read) == 0 {
		t.Error("SessionCapabilities should include baseline filesystem")
	}
	if combined.Network == nil || len(combined.Network.Egress) == 0 {
		t.Error("SessionCapabilities should include session network")
	}
}

func TestManager_Persist(t *testing.T) {
	// Create a temp config file.
	dir := t.TempDir()
	configPath := filepath.Join(dir, "agentcontainer.json")

	initial := `{
  "name": "test",
  "image": "alpine:3"
}`
	if err := os.WriteFile(configPath, []byte(initial), 0o644); err != nil {
		t.Fatalf("writing initial config: %v", err)
	}

	baseline := &config.Capabilities{}

	in := strings.NewReader("s\n")
	out := &bytes.Buffer{}

	approver := NewTerminalApprover(WithInput(in), WithOutput(out))
	mgr := NewManager(approver, configPath, baseline)

	// Approve a shell capability.
	req := Request{
		Category: "shell",
		Action:   "execute git",
		Capability: &config.ShellCaps{
			Commands: []config.ShellCommand{{Binary: "git"}},
		},
	}

	_, err := mgr.Check(req)
	if err != nil {
		t.Fatalf("Check() error: %v", err)
	}

	// Persist all session capabilities.
	if err := mgr.Persist(); err != nil {
		t.Fatalf("Persist() error: %v", err)
	}

	// Verify the config file was updated.
	cfg, err := config.ParseFile(configPath)
	if err != nil {
		t.Fatalf("ParseFile() error: %v", err)
	}

	if cfg.Agent == nil || cfg.Agent.Capabilities == nil {
		t.Fatal("config should have agent.capabilities after persist")
	}
	if cfg.Agent.Capabilities.Shell == nil {
		t.Fatal("config should have shell capabilities after persist")
	}
	if len(cfg.Agent.Capabilities.Shell.Commands) == 0 {
		t.Fatal("config should have shell commands after persist")
	}
	if cfg.Agent.Capabilities.Shell.Commands[0].Binary != "git" {
		t.Errorf("persisted binary = %q, want %q", cfg.Agent.Capabilities.Shell.Commands[0].Binary, "git")
	}
}

func TestManager_Check_AllowPersist_ImmediateSave(t *testing.T) {
	// Create a temp config file.
	dir := t.TempDir()
	configPath := filepath.Join(dir, "agentcontainer.json")

	initial := `{
  "name": "test",
  "image": "alpine:3"
}`
	if err := os.WriteFile(configPath, []byte(initial), 0o644); err != nil {
		t.Fatalf("writing initial config: %v", err)
	}

	in := strings.NewReader("p\n")
	out := &bytes.Buffer{}

	approver := NewTerminalApprover(WithInput(in), WithOutput(out))
	mgr := NewManager(approver, configPath, nil)

	// Approve with persist.
	req := Request{
		Category: "network",
		Action:   "connect to api.example.com",
		Capability: &config.NetworkCaps{
			Egress: []config.EgressRule{{Host: "api.example.com", Port: 443}},
		},
	}

	approved, err := mgr.Check(req)
	if err != nil {
		t.Fatalf("Check() error: %v", err)
	}
	if !approved {
		t.Error("Check() = false, want true for allow-persist")
	}

	// Verify config was saved immediately (without calling Persist).
	cfg, err := config.ParseFile(configPath)
	if err != nil {
		t.Fatalf("ParseFile() error: %v", err)
	}

	if cfg.Agent == nil || cfg.Agent.Capabilities == nil {
		t.Fatal("config should have agent.capabilities after allow-persist")
	}
	if cfg.Agent.Capabilities.Network == nil {
		t.Fatal("config should have network capabilities after allow-persist")
	}
	if len(cfg.Agent.Capabilities.Network.Egress) == 0 {
		t.Fatal("config should have egress rules after allow-persist")
	}
}

func TestNewManager_NilBaseline(t *testing.T) {
	out := &bytes.Buffer{}
	approver := NewTerminalApprover(WithOutput(out))

	mgr := NewManager(approver, "/dev/null", nil)

	// Should not panic and session capabilities should be empty but valid.
	caps := mgr.SessionCapabilities()
	if caps == nil {
		t.Error("SessionCapabilities should not be nil even with nil baseline")
	}
}
