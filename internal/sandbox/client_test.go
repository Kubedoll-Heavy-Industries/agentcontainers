package sandbox

import (
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
)

func newTestClient(t *testing.T, handler http.Handler) *Client {
	t.Helper()
	dir := t.TempDir()
	sockPath := filepath.Join(dir, "test.sock")
	l, err := net.Listen("unix", sockPath)
	if err != nil {
		t.Fatalf("listen unix: %v", err)
	}
	srv := httptest.NewUnstartedServer(handler)
	srv.Listener = l
	srv.Start()
	t.Cleanup(srv.Close)
	c, err := NewClient(WithSocketPath(sockPath))
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	return c
}

func TestHealth(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(HealthResponse{ //nolint:errcheck
			Status:  "healthy",
			Version: "v0.12.0",
			VMs:     2,
		})
	})

	c := newTestClient(t, mux)
	h, err := c.Health(context.Background())
	if err != nil {
		t.Fatalf("Health: %v", err)
	}
	if h.Status != "healthy" {
		t.Errorf("Status = %q, want %q", h.Status, "healthy")
	}
	if h.Version != "v0.12.0" {
		t.Errorf("Version = %q, want %q", h.Version, "v0.12.0")
	}
	if h.VMs != 2 {
		t.Errorf("VMs = %d, want %d", h.VMs, 2)
	}
}

func TestCreateVM(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/vm", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		var req VMCreateRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		if req.AgentName == "" {
			http.Error(w, "agent_name required", http.StatusBadRequest)
			return
		}
		if req.WorkspaceDir == "" {
			http.Error(w, "workspace_dir required", http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(VMCreateResponse{ //nolint:errcheck
			VMID: "vm-abc123",
			VMConfig: VMConfig{
				SocketPath: "/run/sandbox/vm-abc123.sock",
			},
			Started: true,
		})
	})

	c := newTestClient(t, mux)
	resp, err := c.CreateVM(context.Background(), &VMCreateRequest{
		AgentName:    "shell",
		WorkspaceDir: "/workspace",
	})
	if err != nil {
		t.Fatalf("CreateVM: %v", err)
	}
	if resp.VMID != "vm-abc123" {
		t.Errorf("VMID = %q, want %q", resp.VMID, "vm-abc123")
	}
	if resp.VMConfig.SocketPath != "/run/sandbox/vm-abc123.sock" {
		t.Errorf("SocketPath = %q, want %q", resp.VMConfig.SocketPath, "/run/sandbox/vm-abc123.sock")
	}
	if !resp.Started {
		t.Error("Started = false, want true")
	}
}

func TestCreateVM_ServerError(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/vm", func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "internal failure", http.StatusInternalServerError)
	})

	c := newTestClient(t, mux)
	_, err := c.CreateVM(context.Background(), &VMCreateRequest{
		AgentName:    "shell",
		WorkspaceDir: "/workspace",
	})
	if err == nil {
		t.Fatal("expected error for 500 response, got nil")
	}
	if got := err.Error(); !containsSubstring(got, "500") {
		t.Errorf("error = %q, want it to contain %q", got, "500")
	}
}

func TestListVMs(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/vm", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode([]VMListEntry{ //nolint:errcheck
			{
				VMID:         "vm-1",
				VMName:       "agent-1",
				Agent:        "shell",
				WorkspaceDir: "/workspace/1",
				CreatedAt:    "2026-03-01T00:00:00Z",
				Active:       true,
				Status:       "running",
				VMConfig:     VMConfig{SocketPath: "/run/sandbox/vm-1.sock"},
			},
			{
				VMID:         "vm-2",
				VMName:       "agent-2",
				Agent:        "shell",
				WorkspaceDir: "/workspace/2",
				CreatedAt:    "2026-03-01T01:00:00Z",
				Active:       false,
				Status:       "stopped",
				VMConfig:     VMConfig{SocketPath: "/run/sandbox/vm-2.sock"},
			},
		})
	})

	c := newTestClient(t, mux)
	vms, err := c.ListVMs(context.Background())
	if err != nil {
		t.Fatalf("ListVMs: %v", err)
	}
	if len(vms) != 2 {
		t.Fatalf("len(vms) = %d, want 2", len(vms))
	}
	if vms[0].VMID != "vm-1" {
		t.Errorf("vms[0].VMID = %q, want %q", vms[0].VMID, "vm-1")
	}
	if vms[0].Active != true {
		t.Error("vms[0].Active = false, want true")
	}
	if vms[1].VMID != "vm-2" {
		t.Errorf("vms[1].VMID = %q, want %q", vms[1].VMID, "vm-2")
	}
	if vms[1].Status != "stopped" {
		t.Errorf("vms[1].Status = %q, want %q", vms[1].Status, "stopped")
	}
}

func TestListVMs_Empty(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/vm", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte("[]")) //nolint:errcheck
	})

	c := newTestClient(t, mux)
	vms, err := c.ListVMs(context.Background())
	if err != nil {
		t.Fatalf("ListVMs: %v", err)
	}
	if vms == nil {
		t.Fatal("vms is nil, want empty slice")
	}
	if len(vms) != 0 {
		t.Errorf("len(vms) = %d, want 0", len(vms))
	}
}

func TestInspectVM(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/vm/test-vm", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(VMInspectResponse{ //nolint:errcheck
			VMID:            "vm-abc123",
			VMName:          "test-vm",
			Agent:           "shell",
			WorkspaceDir:    "/workspace",
			RegisteredAt:    "2026-03-01T00:00:00Z",
			LastSeen:        "2026-03-01T01:00:00Z",
			IPAddresses:     []string{"10.0.0.2"},
			Subnets:         []string{"10.0.0.0/24"},
			CredentialCount: 3,
			VMConfig:        VMConfig{SocketPath: "/run/sandbox/vm-abc123.sock"},
		})
	})

	c := newTestClient(t, mux)
	v, err := c.InspectVM(context.Background(), "test-vm")
	if err != nil {
		t.Fatalf("InspectVM: %v", err)
	}
	if v.VMID != "vm-abc123" {
		t.Errorf("VMID = %q, want %q", v.VMID, "vm-abc123")
	}
	if v.VMName != "test-vm" {
		t.Errorf("VMName = %q, want %q", v.VMName, "test-vm")
	}
	if v.Agent != "shell" {
		t.Errorf("Agent = %q, want %q", v.Agent, "shell")
	}
	if v.WorkspaceDir != "/workspace" {
		t.Errorf("WorkspaceDir = %q, want %q", v.WorkspaceDir, "/workspace")
	}
	if v.RegisteredAt != "2026-03-01T00:00:00Z" {
		t.Errorf("RegisteredAt = %q, want %q", v.RegisteredAt, "2026-03-01T00:00:00Z")
	}
	if v.LastSeen != "2026-03-01T01:00:00Z" {
		t.Errorf("LastSeen = %q, want %q", v.LastSeen, "2026-03-01T01:00:00Z")
	}
	if len(v.IPAddresses) != 1 || v.IPAddresses[0] != "10.0.0.2" {
		t.Errorf("IPAddresses = %v, want [10.0.0.2]", v.IPAddresses)
	}
	if len(v.Subnets) != 1 || v.Subnets[0] != "10.0.0.0/24" {
		t.Errorf("Subnets = %v, want [10.0.0.0/24]", v.Subnets)
	}
	if v.CredentialCount != 3 {
		t.Errorf("CredentialCount = %d, want %d", v.CredentialCount, 3)
	}
	if v.VMConfig.SocketPath != "/run/sandbox/vm-abc123.sock" {
		t.Errorf("SocketPath = %q, want %q", v.VMConfig.SocketPath, "/run/sandbox/vm-abc123.sock")
	}
}

func TestInspectVM_NotFound(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/vm/nonexistent", func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "VM not found", http.StatusNotFound)
	})

	c := newTestClient(t, mux)
	_, err := c.InspectVM(context.Background(), "nonexistent")
	if err == nil {
		t.Fatal("expected error for 404 response, got nil")
	}
	if got := err.Error(); !containsSubstring(got, "404") {
		t.Errorf("error = %q, want it to contain %q", got, "404")
	}
}

func TestStopVM(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/vm/test-vm/stop", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"message":"VM stopped"}`)) //nolint:errcheck
	})

	c := newTestClient(t, mux)
	err := c.StopVM(context.Background(), "test-vm")
	if err != nil {
		t.Fatalf("StopVM: %v", err)
	}
}

func TestDeleteVM(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/vm/test-vm", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodDelete {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	})

	c := newTestClient(t, mux)
	err := c.DeleteVM(context.Background(), "test-vm")
	if err != nil {
		t.Fatalf("DeleteVM: %v", err)
	}
}

func TestKeepalive(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/vm/test-vm/keepalive", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"message":"Keepalive received"}`)) //nolint:errcheck
	})

	c := newTestClient(t, mux)
	err := c.Keepalive(context.Background(), "test-vm")
	if err != nil {
		t.Fatalf("Keepalive: %v", err)
	}
}

func TestUpdateProxyConfig(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/network/proxyconfig", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		body, err := io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		var req ProxyConfigRequest
		if err := json.Unmarshal(body, &req); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		if req.VMName == "" {
			http.Error(w, "vm_name required", http.StatusBadRequest)
			return
		}
		if req.Policy == "" {
			http.Error(w, "policy required", http.StatusBadRequest)
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"message":"proxy config updated"}`)) //nolint:errcheck
	})

	c := newTestClient(t, mux)
	err := c.UpdateProxyConfig(context.Background(), &ProxyConfigRequest{
		VMName:     "test-vm",
		AllowHosts: []string{"api.github.com"},
		Policy:     "DENY",
	})
	if err != nil {
		t.Fatalf("UpdateProxyConfig: %v", err)
	}
}

func TestSocketPath_EnvOverride(t *testing.T) {
	dir := t.TempDir()
	customPath := filepath.Join(dir, "custom.sock")
	t.Setenv("DOCKER_SANDBOXES_API", customPath)

	// NewClient should succeed and use the env var path (no socket
	// actually needs to be listening for construction to succeed).
	c, err := NewClient()
	if err != nil {
		t.Fatalf("NewClient with env override: %v", err)
	}
	if c == nil {
		t.Fatal("client is nil")
	}
}

// containsSubstring is a tiny helper to avoid importing strings in tests.
func containsSubstring(s, substr string) bool {
	return len(s) >= len(substr) && searchSubstring(s, substr)
}

func searchSubstring(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
