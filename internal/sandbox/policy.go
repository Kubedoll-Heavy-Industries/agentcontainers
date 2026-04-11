package sandbox

import (
	"fmt"

	"github.com/Kubedoll-Heavy-Industries/agentcontainers/internal/config"
)

const metadataEndpoint = "169.254.169.254/32"

// TranslatePolicy converts agentcontainer.json capabilities into a Sandbox
// ProxyConfigRequest suitable for POST /network/proxyconfig.
//
// The proxy operates at L7 (HTTP/HTTPS) so the Protocol field on egress rules
// is intentionally ignored here. UDP and raw protocol enforcement is handled by
// the BPF cgroup hooks inside the VM (sendmsg4/sendmsg6), not by the proxy.
func TranslatePolicy(vmName string, caps *config.Capabilities) *ProxyConfigRequest {
	req := &ProxyConfigRequest{
		VMName:      vmName,
		Policy:      "DENY",
		BypassHosts: []string{"localhost", "127.0.0.1", "::1"},
		BlockCIDRs:  []string{metadataEndpoint},
	}

	if caps == nil || caps.Network == nil {
		return req
	}

	for _, rule := range caps.Network.Egress {
		port := rule.Port
		if port == 0 {
			port = 443
		}
		req.AllowHosts = append(req.AllowHosts, fmt.Sprintf("%s:%d", rule.Host, port))
	}

	req.BlockCIDRs = append(req.BlockCIDRs, caps.Network.Deny...)

	return req
}
