# Go CLI Integration Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Wire the new enforcer hooks into the Go CLI: seccomp profile generation, deny-set policy application from config, learn mode, built-in tool profiles, and process-scoped secret ACLs.

**Architecture:** The Go CLI translates `agentcontainer.json` capabilities into gRPC requests to the enforcer. Seccomp profiles are generated at container creation time and applied via Docker's SecurityOpt. Learn mode uses a new CLI command that starts the container with observation-mode deny-sets. Built-in tool profiles are embedded in the binary as JSONC files.

**Tech Stack:** Go, Cobra CLI, Docker SDK (moby), gRPC (tonic client), embedded filesystem

**Depends on:** `2026-04-21-enforcer-hook-expansion.md` (the Rust BPF hooks must exist for the gRPC calls to succeed)

**Reference:** `prd/PRD-008-enforcer-hook-expansion.md`

---

## File Structure

### New files

| File | Responsibility |
|------|---------------|
| `internal/seccomp/profile.go` | Generate seccomp profiles from capabilities |
| `internal/seccomp/profile_test.go` | Tests for seccomp generation |
| `internal/profiles/embed.go` | Embedded tool profiles (npm, node, git, etc.) |
| `internal/profiles/profiles/npm.jsonc` | npm process-tree profile |
| `internal/profiles/profiles/node.jsonc` | node process-tree profile |
| `internal/profiles/profiles/git.jsonc` | git process-tree profile |
| `internal/profiles/profiles/python.jsonc` | python/pip process-tree profile |
| `internal/profiles/profiles/cargo.jsonc` | cargo process-tree profile |
| `internal/profiles/profiles/make.jsonc` | make process-tree profile |
| `internal/profiles/merge.go` | Profile merge logic (intersection of allowChildren) |
| `internal/profiles/merge_test.go` | Tests for profile merge |
| `internal/cli/learn.go` | `agentcontainer learn` command |
| `internal/cli/learn_test.go` | Tests for learn command |

### Modified files

| File | Changes |
|------|---------|
| `internal/config/config.go` | Add `Seccomp`, `ProcessPolicy`, `Profiles`, `ListenRules`, `DnsInspection`, `ReverseShellDetection` fields |
| `internal/container/docker.go` | Apply seccomp profile at container creation, call new enforcer RPCs post-start |
| `internal/enforcement/grpc.go` | Add methods for deny-set, bind, reverse shell config RPCs |
| `internal/cli/root.go` | Register `learn` command |
| `internal/cli/run.go` | Wire profile loading, deny-set application, bind policy, reverse shell config |

---

### Task 1: Seccomp profile generation

**Files:**
- Create: `internal/seccomp/profile.go`
- Create: `internal/seccomp/profile_test.go`

- [ ] **Step 1: Write the failing test**

`internal/seccomp/profile_test.go`:

```go
package seccomp

import (
	"encoding/json"
	"testing"
)

func TestGenerateDefault(t *testing.T) {
	profile := Generate("default")
	if profile == nil {
		t.Fatal("expected non-nil profile")
	}

	data, err := json.Marshal(profile)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	// Must be valid JSON.
	var parsed map[string]any
	if err := json.Unmarshal(data, &parsed); err != nil {
		t.Fatalf("not valid JSON: %v", err)
	}

	// Default action must be SCMP_ACT_ALLOW (allowlist model blocks specific syscalls).
	if parsed["defaultAction"] != "SCMP_ACT_ALLOW" {
		t.Errorf("defaultAction = %v, want SCMP_ACT_ALLOW", parsed["defaultAction"])
	}
}

func TestGenerateDefault_BlocksDangerousSyscalls(t *testing.T) {
	profile := Generate("default")

	blocked := blockedSyscalls(profile)
	for _, sc := range []string{"mount", "ptrace", "unshare", "kexec_load", "bpf"} {
		if !blocked[sc] {
			t.Errorf("expected %q to be blocked in default profile", sc)
		}
	}
}

func TestGenerateStrict_BlocksMore(t *testing.T) {
	defaultProfile := Generate("default")
	strictProfile := Generate("strict")

	defaultBlocked := blockedSyscalls(defaultProfile)
	strictBlocked := blockedSyscalls(strictProfile)

	if len(strictBlocked) <= len(defaultBlocked) {
		t.Errorf("strict profile should block more syscalls than default: strict=%d, default=%d",
			len(strictBlocked), len(defaultBlocked))
	}
}

func TestGenerateNone_ReturnsNil(t *testing.T) {
	profile := Generate("none")
	if profile != nil {
		t.Error("expected nil profile for 'none' mode")
	}
}

func blockedSyscalls(p *Profile) map[string]bool {
	result := make(map[string]bool)
	if p == nil {
		return result
	}
	for _, sc := range p.Syscalls {
		if sc.Action == "SCMP_ACT_ERRNO" {
			for _, name := range sc.Names {
				result[name] = true
			}
		}
	}
	return result
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test -run TestGenerate ./internal/seccomp/...`
Expected: FAIL — package doesn't exist

- [ ] **Step 3: Implement seccomp profile generation**

`internal/seccomp/profile.go`:

```go
// Package seccomp generates OCI seccomp profiles from agentcontainer capabilities.
package seccomp

// Profile is an OCI-compatible seccomp profile.
type Profile struct {
	DefaultAction string        `json:"defaultAction"`
	Syscalls      []SyscallRule `json:"syscalls"`
}

// SyscallRule defines an action for a set of syscalls.
type SyscallRule struct {
	Names  []string `json:"names"`
	Action string   `json:"action"`
}

// Generate creates a seccomp profile for the given mode.
// Modes: "default", "strict", "none", or a file path (returned as-is, not generated).
// Returns nil for "none" (no custom seccomp — Docker default applies).
func Generate(mode string) *Profile {
	switch mode {
	case "none", "":
		return nil
	case "strict":
		return &Profile{
			DefaultAction: "SCMP_ACT_ALLOW",
			Syscalls: []SyscallRule{
				{Names: dangerousSyscalls, Action: "SCMP_ACT_ERRNO"},
				{Names: strictExtraSyscalls, Action: "SCMP_ACT_ERRNO"},
			},
		}
	default: // "default" or unrecognized
		return &Profile{
			DefaultAction: "SCMP_ACT_ALLOW",
			Syscalls: []SyscallRule{
				{Names: dangerousSyscalls, Action: "SCMP_ACT_ERRNO"},
			},
		}
	}
}

// dangerousSyscalls are blocked in both default and strict modes.
var dangerousSyscalls = []string{
	"mount", "umount2", "ptrace", "unshare", "setns",
	"pivot_root", "kexec_load", "kexec_file_load",
	"bpf", "add_key", "keyctl", "request_key",
	"userfaultfd", "perf_event_open",
	"init_module", "finit_module", "delete_module",
	"reboot", "swapon", "swapoff",
	"sethostname", "setdomainname",
	"iopl", "ioperm",
	"create_module", "get_kernel_syms", "query_module",
	"nfsservctl", "acct", "lookup_dcookie",
	"mbind", "move_pages",
}

// strictExtraSyscalls are additionally blocked in strict mode.
var strictExtraSyscalls = []string{
	"clone3", "personality", "vhangup",
	"open_by_handle_at", "name_to_handle_at",
	"kcmp", "process_vm_readv", "process_vm_writev",
}
```

- [ ] **Step 4: Run tests**

Run: `go test -race ./internal/seccomp/...`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add internal/seccomp/
git commit -m "feat: seccomp profile generation from agentcontainer capabilities"
```

---

### Task 2: Config schema extensions

**Files:**
- Modify: `internal/config/config.go`

- [ ] **Step 1: Add new fields to config types**

Add to `AgentConfig`:

```go
// Seccomp controls the container's seccomp profile.
// Values: "default" (generated restrictive), "strict", "none", or a file path.
Seccomp string `json:"seccomp,omitempty"`
```

Add to `Capabilities`:

```go
// ProcessPolicy declares process-tree enforcement rules.
ProcessPolicy *ProcessPolicyConfig `json:"processPolicy,omitempty"`
```

Add to `ShellCaps`:

```go
// Profiles lists built-in tool profile names to apply (e.g., "npm@1", "node@1").
Profiles []string `json:"profiles,omitempty"`

// ReverseShellDetection controls reverse shell detection mode.
// Values: "enforce" (default), "log", "off".
ReverseShellDetection string `json:"reverseShellDetection,omitempty"`
```

Add to `NetworkCaps`:

```go
// Listen defines allowed listening ports. Empty = no listening (default-deny).
Listen []ListenRule `json:"listen,omitempty"`

// DnsInspection configures DNS payload inspection for exfiltration detection.
DnsInspection *DnsInspectionConfig `json:"dnsInspection,omitempty"`
```

Add new types:

```go
// ProcessPolicyConfig declares per-binary child spawn restrictions.
type ProcessPolicyConfig struct {
	Rules map[string]ProcessRule `json:"rules,omitempty"`
}

// ProcessRule defines which children a binary may spawn.
type ProcessRule struct {
	AllowChildren []string `json:"allowChildren"`
}

// ListenRule defines an allowed listening port.
type ListenRule struct {
	Port     int    `json:"port"`
	Protocol string `json:"protocol,omitempty"` // "tcp" (default) or "udp"
}

// DnsInspectionConfig controls DNS payload inspection.
type DnsInspectionConfig struct {
	Mode           string `json:"mode,omitempty"`           // "off" (default), "log", "enforce"
	MaxQueryLength int    `json:"maxQueryLength,omitempty"` // Default: 128
}
```

- [ ] **Step 2: Run existing config tests to ensure no regression**

Run: `go test -race ./internal/config/...`
Expected: PASS (new fields are optional, existing configs unchanged)

- [ ] **Step 3: Commit**

```bash
git add internal/config/config.go
git commit -m "feat: add process policy, seccomp, bind, DNS inspection config fields"
```

---

### Task 3: Built-in tool profiles

**Files:**
- Create: `internal/profiles/embed.go`
- Create: `internal/profiles/profiles/npm.jsonc`
- Create: `internal/profiles/profiles/node.jsonc`
- Create: `internal/profiles/profiles/git.jsonc`
- Create: `internal/profiles/profiles/python.jsonc`
- Create: `internal/profiles/profiles/cargo.jsonc`
- Create: `internal/profiles/profiles/make.jsonc`

- [ ] **Step 1: Create profile JSONC files**

`internal/profiles/profiles/npm.jsonc`:
```jsonc
{
  "name": "npm",
  "version": 1,
  "binary": "npm",
  "allowChildren": ["node", "npm", "npx"],
  "transitions": {
    "node": "node@1"
  }
}
```

`internal/profiles/profiles/node.jsonc`:
```jsonc
{
  "name": "node",
  "version": 1,
  "binary": "node",
  "allowChildren": ["node"]
}
```

`internal/profiles/profiles/git.jsonc`:
```jsonc
{
  "name": "git",
  "version": 1,
  "binary": "git",
  "allowChildren": ["git", "ssh", "gpg", "git-remote-https"]
}
```

`internal/profiles/profiles/python.jsonc`:
```jsonc
{
  "name": "python",
  "version": 1,
  "binary": "python3",
  "allowChildren": ["python3", "pip", "pip3"]
}
```

`internal/profiles/profiles/cargo.jsonc`:
```jsonc
{
  "name": "cargo",
  "version": 1,
  "binary": "cargo",
  "allowChildren": ["rustc", "cargo"]
}
```

`internal/profiles/profiles/make.jsonc`:
```jsonc
{
  "name": "make",
  "version": 1,
  "binary": "make",
  "allowChildren": ["sh", "gcc", "g++", "cc", "ld", "ar", "make"],
  "transitions": {
    "sh": "make-sh@1"
  }
}
```

- [ ] **Step 2: Create embed.go with profile loader**

`internal/profiles/embed.go`:

```go
// Package profiles provides built-in process-tree tool profiles.
package profiles

import (
	"embed"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/tailscale/hujson"
)

//go:embed profiles/*.jsonc
var profileFS embed.FS

// Profile represents a process-tree tool profile.
type Profile struct {
	Name           string            `json:"name"`
	Version        int               `json:"version"`
	Binary         string            `json:"binary"`
	AllowChildren  []string          `json:"allowChildren"`
	Transitions    map[string]string `json:"transitions,omitempty"`
}

// Key returns the profile identifier (e.g., "npm@1").
func (p *Profile) Key() string {
	return fmt.Sprintf("%s@%d", p.Name, p.Version)
}

// LoadBuiltin loads a built-in profile by key (e.g., "npm@1").
func LoadBuiltin(key string) (*Profile, error) {
	parts := strings.SplitN(key, "@", 2)
	if len(parts) != 2 {
		return nil, fmt.Errorf("invalid profile key %q (expected name@version)", key)
	}
	name := parts[0]

	data, err := profileFS.ReadFile("profiles/" + name + ".jsonc")
	if err != nil {
		return nil, fmt.Errorf("profile %q not found: %w", key, err)
	}

	// Strip JSONC comments.
	standardized, err := hujson.Standardize(data)
	if err != nil {
		return nil, fmt.Errorf("profile %q: %w", key, err)
	}

	var p Profile
	if err := json.Unmarshal(standardized, &p); err != nil {
		return nil, fmt.Errorf("profile %q: %w", key, err)
	}

	if p.Key() != key {
		return nil, fmt.Errorf("profile %q: key mismatch (file contains %q)", key, p.Key())
	}

	return &p, nil
}

// ListBuiltin returns all available built-in profile keys.
func ListBuiltin() []string {
	entries, _ := profileFS.ReadDir("profiles")
	var keys []string
	for _, e := range entries {
		if strings.HasSuffix(e.Name(), ".jsonc") {
			name := strings.TrimSuffix(e.Name(), ".jsonc")
			data, err := profileFS.ReadFile("profiles/" + e.Name())
			if err != nil {
				continue
			}
			std, err := hujson.Standardize(data)
			if err != nil {
				continue
			}
			var p Profile
			if err := json.Unmarshal(std, &p); err != nil {
				continue
			}
			keys = append(keys, fmt.Sprintf("%s@%d", name, p.Version))
		}
	}
	return keys
}
```

- [ ] **Step 3: Write tests**

```go
package profiles

import "testing"

func TestLoadBuiltin_npm(t *testing.T) {
	p, err := LoadBuiltin("npm@1")
	if err != nil {
		t.Fatalf("LoadBuiltin: %v", err)
	}
	if p.Binary != "npm" {
		t.Errorf("binary = %q, want npm", p.Binary)
	}
	if len(p.AllowChildren) == 0 {
		t.Error("expected non-empty allowChildren")
	}
}

func TestLoadBuiltin_NotFound(t *testing.T) {
	_, err := LoadBuiltin("nonexistent@1")
	if err == nil {
		t.Error("expected error for nonexistent profile")
	}
}

func TestListBuiltin(t *testing.T) {
	keys := ListBuiltin()
	if len(keys) < 5 {
		t.Errorf("expected at least 5 built-in profiles, got %d", len(keys))
	}
}
```

- [ ] **Step 4: Run tests**

Run: `go test -race ./internal/profiles/...`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add internal/profiles/
git commit -m "feat: built-in process-tree tool profiles (npm, node, git, python, cargo, make)"
```

---

### Task 4: Profile merge logic

**Files:**
- Create: `internal/profiles/merge.go`
- Create: `internal/profiles/merge_test.go`

- [ ] **Step 1: Write failing test**

```go
package profiles

import "testing"

func TestMerge_Intersection(t *testing.T) {
	a := &Profile{Name: "npm", Version: 1, Binary: "npm", AllowChildren: []string{"node", "npx"}}
	b := &Profile{Name: "npm", Version: 1, Binary: "npm", AllowChildren: []string{"node"}}

	merged := Merge(a, b)
	if len(merged.AllowChildren) != 1 || merged.AllowChildren[0] != "node" {
		t.Errorf("expected [node], got %v", merged.AllowChildren)
	}
}

func TestMerge_EmptyRestricts(t *testing.T) {
	a := &Profile{Name: "npm", Version: 1, Binary: "npm", AllowChildren: []string{"node"}}
	b := &Profile{Name: "npm", Version: 1, Binary: "npm", AllowChildren: []string{}}

	merged := Merge(a, b)
	if len(merged.AllowChildren) != 0 {
		t.Errorf("expected empty, got %v", merged.AllowChildren)
	}
}
```

- [ ] **Step 2: Implement merge**

`internal/profiles/merge.go`:

```go
package profiles

// Merge combines two profiles for the same binary using intersection semantics.
// The result allows only children present in BOTH profiles (most restrictive wins).
func Merge(a, b *Profile) *Profile {
	bSet := make(map[string]bool, len(b.AllowChildren))
	for _, c := range b.AllowChildren {
		bSet[c] = true
	}

	var intersection []string
	for _, c := range a.AllowChildren {
		if bSet[c] {
			intersection = append(intersection, c)
		}
	}

	return &Profile{
		Name:          a.Name,
		Version:       a.Version,
		Binary:        a.Binary,
		AllowChildren: intersection,
		Transitions:   a.Transitions, // First profile's transitions win
	}
}
```

- [ ] **Step 3: Run tests**

Run: `go test -race ./internal/profiles/...`
Expected: PASS

- [ ] **Step 4: Commit**

```bash
git add internal/profiles/merge.go internal/profiles/merge_test.go
git commit -m "feat: profile merge with intersection semantics"
```

---

### Task 5: Wire seccomp + deny-sets + bind + reverse shell into container start

**Files:**
- Modify: `internal/container/docker.go`
- Modify: `internal/enforcement/grpc.go`
- Modify: `internal/cli/run.go`

- [ ] **Step 1: Add seccomp profile to container creation in docker.go**

In the container creation path, if a seccomp profile is configured, marshal it to JSON and add to `SecurityOpt`:

```go
if seccompProfile != nil {
    data, err := json.Marshal(seccompProfile)
    if err != nil {
        return fmt.Errorf("marshal seccomp profile: %w", err)
    }
    hostConfig.SecurityOpt = append(hostConfig.SecurityOpt, "seccomp="+string(data))
}
```

- [ ] **Step 2: Add gRPC methods to enforcement/grpc.go**

Add methods to `GRPCStrategy`:

```go
func (s *GRPCStrategy) ApplyDenySetPolicy(ctx context.Context, containerID string, req *enforcerapi.ApplyDenySetPolicyRequest) error
func (s *GRPCStrategy) ApplyBindPolicy(ctx context.Context, containerID string, req *enforcerapi.BindPolicyRequest) error
func (s *GRPCStrategy) ConfigureReverseShell(ctx context.Context, containerID string, mode string) error
```

Each method is a simple gRPC call forwarding the request to the enforcer.

- [ ] **Step 3: Wire into run.go post-start flow**

In `runRun`, after `Apply` succeeds:
1. Load profiles from config (`agent.capabilities.shell.profiles`)
2. Merge built-in profiles with inline `processPolicy`
3. Call `ApplyDenySetPolicy` with the merged profiles
4. Call `ApplyBindPolicy` with `network.listen` rules
5. Call `ConfigureReverseShell` with `shell.reverseShellDetection` mode
6. Generate and apply seccomp profile from `agent.seccomp`

- [ ] **Step 4: Run full test suite**

Run: `go build ./... && go vet ./... && go test -race ./...`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add internal/container/docker.go internal/enforcement/grpc.go internal/cli/run.go
git commit -m "feat: wire seccomp, deny-sets, bind policy, and reverse shell config into container start"
```

---

### Task 6: Learn mode command

**Files:**
- Create: `internal/cli/learn.go`
- Create: `internal/cli/learn_test.go`
- Modify: `internal/cli/root.go`

- [ ] **Step 1: Write failing test**

```go
package cli

import (
	"bytes"
	"testing"
)

func TestLearnCmd_NoConfig(t *testing.T) {
	cmd := newLearnCmd()
	cmd.SetArgs([]string{})
	var buf bytes.Buffer
	cmd.SetOut(&buf)
	cmd.SetErr(&buf)

	err := cmd.Execute()
	if err == nil {
		t.Error("expected error when no config exists")
	}
}
```

- [ ] **Step 2: Implement learn command**

`internal/cli/learn.go`:

The learn command follows the same flow as `run` but:
1. Passes a `learn_mode: true` flag to the enforcer (via a new field on `ApplyDenySetPolicy` or a separate RPC)
2. The enforcer attaches the same hooks but in observation mode (allow all, emit events)
3. On container stop, collects all `DenySetEvent` events from the stream
4. Builds a process-tree graph from the observed (parent, child) pairs
5. Writes `process-profile.json` to the working directory

Also support `agentcontainer learn --from-session` which reads the audit log from the last `run` session and extracts approved (parent, child) pairs.

- [ ] **Step 3: Register in root.go**

Add `cmd.AddCommand(newLearnCmd())` in `newRootCmd()`.

- [ ] **Step 4: Run tests**

Run: `go test -race ./internal/cli/...`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add internal/cli/learn.go internal/cli/learn_test.go internal/cli/root.go
git commit -m "feat: agentcontainer learn command for process-tree profile generation"
```

---

### Task 7: Final integration test + cleanup

- [ ] **Step 1: Run full build + vet + test**

```bash
go build ./... && go vet ./... && go test -race ./...
```

- [ ] **Step 2: Run Rust tests**

```bash
cargo test --manifest-path enforcer/Cargo.toml -p agentcontainer-common
cargo test --manifest-path enforcer/Cargo.toml -p agentcontainer-enforcer --lib
```

- [ ] **Step 3: Format**

```bash
cargo fmt --manifest-path enforcer/Cargo.toml --all
```

- [ ] **Step 4: Commit any final fixes**

```bash
git add -A
git commit -m "chore: final cleanup after enforcer hook expansion + Go integration"
```
