package sandbox

// HealthResponse is returned by GET /health.
type HealthResponse struct {
	Status  string `json:"status"`
	Version string `json:"version"`
	VMs     int    `json:"vms"`
}

// VMCreateRequest is the body for POST /vm.
type VMCreateRequest struct {
	AgentName         string                       `json:"agent_name"`
	WorkspaceDir      string                       `json:"workspace_dir"`
	VMName            string                       `json:"vm_name,omitempty"`
	ExistingWorkspace bool                         `json:"existing_workspace,omitempty"`
	Mounts            []SandboxMount               `json:"mounts,omitempty"`
	ServiceDomains    map[string]string            `json:"service_domains,omitempty"`
	ServiceAuthConfig map[string]ServiceAuthConfig `json:"service_auth_config,omitempty"`
	CredentialSources map[string]CredentialSource  `json:"credential_sources,omitempty"`
	Policy            *PolicyConfig                `json:"policy,omitempty"`
}

// SandboxMount represents an additional mount for a sandbox VM.
type SandboxMount struct {
	Source   string `json:"source"`
	Target   string `json:"target,omitempty"`
	ReadOnly bool   `json:"readonly,omitempty"`
}

// ServiceAuthConfig defines per-domain header injection by the MITM proxy.
type ServiceAuthConfig struct {
	HeaderName string `json:"header_name"`
}

// CredentialSource describes where to find a credential on the host.
type CredentialSource struct {
	Source string `json:"source"`
	Path   string `json:"path,omitempty"`
}

// PolicyConfig is the proxy-level network policy passed in VM creation.
type PolicyConfig struct {
	Default string `json:"default,omitempty"` // "allow" or "deny"
}

// VMCreateResponse is returned by POST /vm.
type VMCreateResponse struct {
	VMID         string            `json:"vm_id"`
	VMConfig     VMConfig          `json:"vm_config"`
	CACertPath   string            `json:"ca_cert_path,omitempty"`
	CACertData   string            `json:"ca_cert_data,omitempty"`
	ProxyEnvVars map[string]string `json:"proxy_env_vars,omitempty"`
	Started      bool              `json:"started"`
}

// VMConfig holds the per-VM Docker daemon socket path.
type VMConfig struct {
	SocketPath string `json:"socketPath,omitempty"`
}

// VMListEntry is one element of the GET /vm response array.
type VMListEntry struct {
	VMID         string   `json:"vm_id"`
	VMName       string   `json:"vm_name"`
	Agent        string   `json:"agent"`
	WorkspaceDir string   `json:"workspace_dir"`
	CreatedAt    string   `json:"created_at"`
	Active       bool     `json:"active"`
	Status       string   `json:"status"`
	VMConfig     VMConfig `json:"vm_config"`
}

// VMInspectResponse is returned by GET /vm/{name}.
type VMInspectResponse struct {
	VMID            string   `json:"vm_id"`
	VMName          string   `json:"vm_name"`
	Agent           string   `json:"agent"`
	WorkspaceDir    string   `json:"workspace_dir"`
	RegisteredAt    string   `json:"registered_at"`
	LastSeen        string   `json:"last_seen"`
	IPAddresses     []string `json:"ip_addresses"`
	Subnets         []string `json:"subnets"`
	CredentialCount int      `json:"credential_count"`
	VMConfig        VMConfig `json:"vm_config"`
}

// ProxyConfigRequest is the body for POST /network/proxyconfig.
type ProxyConfigRequest struct {
	VMName      string   `json:"vm_name"`
	AllowHosts  []string `json:"allow_hosts,omitempty"`
	BlockHosts  []string `json:"block_hosts,omitempty"`
	BypassHosts []string `json:"bypass_hosts,omitempty"`
	AllowCIDRs  []string `json:"allow_cidrs,omitempty"`
	BlockCIDRs  []string `json:"block_cidrs,omitempty"`
	BypassCIDRs []string `json:"bypass_cidrs,omitempty"`
	Policy      string   `json:"policy"` // "ALLOW" or "DENY"
}
