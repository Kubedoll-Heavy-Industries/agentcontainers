package policy

import (
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/Kubedoll-Heavy-Industries/agentcontainers/internal/config"
)

// defaultWorkspaceTarget is the in-container mount point for the workspace.
const defaultWorkspaceTarget = "/workspace"

// Resolve translates agent capability declarations into a ContainerPolicy.
// It starts from a default-deny baseline and selectively opens access based
// on the declared capabilities. A nil Capabilities pointer produces the
// strictest possible policy.
func Resolve(caps *config.Capabilities) *ContainerPolicy {
	p := defaultPolicy()

	if caps == nil {
		return p
	}

	resolveFilesystem(p, caps.Filesystem)
	resolveNetwork(p, caps.Network)
	resolveShell(p, caps.Shell)
	resolveGit(p, caps.Git)

	return p
}

// defaultPolicy returns the strictest possible container policy.
func defaultPolicy() *ContainerPolicy {
	return &ContainerPolicy{
		CapDrop:        []string{"ALL"},
		SecurityOpt:    []string{"no-new-privileges"},
		ReadonlyRootfs: true,
		NetworkMode:    "none",
	}
}

// mountTarget computes the in-container mount point for a source path by
// stripping the leading slash and joining it under the workspace root.
// For example, "/home/user/project" becomes "/workspace/home/user/project".
func mountTarget(source string) string {
	return filepath.Join(defaultWorkspaceTarget, strings.TrimPrefix(source, "/"))
}

// resolveFilesystem maps filesystem capability declarations to mount policies.
// If the same path appears in both Read and Write, only a read-write mount is
// created (Write wins over Read).
func resolveFilesystem(p *ContainerPolicy, fs *config.FilesystemCaps) {
	if fs == nil {
		return
	}

	denied := make(map[string]bool, len(fs.Deny))
	for _, pattern := range fs.Deny {
		denied[pattern] = true
	}

	// Build a set of write paths so we can skip duplicates in Read.
	writePaths := make(map[string]bool, len(fs.Write))
	for _, pattern := range fs.Write {
		if !denied[pattern] {
			writePaths[pattern] = true
		}
	}

	for _, pattern := range fs.Read {
		if denied[pattern] {
			continue
		}
		// If the same path is also in Write, skip the read-only mount;
		// the read-write mount below will cover it.
		if writePaths[pattern] {
			continue
		}
		p.AllowedMounts = append(p.AllowedMounts, MountPolicy{
			Source:   pattern,
			Target:   mountTarget(pattern),
			ReadOnly: true,
		})
	}

	for _, pattern := range fs.Write {
		if denied[pattern] {
			continue
		}
		p.AllowedMounts = append(p.AllowedMounts, MountPolicy{
			Source:   pattern,
			Target:   mountTarget(pattern),
			ReadOnly: false,
		})
	}
}

// resolveNetwork maps network capability declarations to network policy.
func resolveNetwork(p *ContainerPolicy, net *config.NetworkCaps) {
	if net == nil {
		return
	}

	if len(net.Egress) > 0 {
		p.NetworkMode = "bridge"
		for _, rule := range net.Egress {
			p.AllowedHosts = append(p.AllowedHosts, rule.Host)
			p.AllowedEgressRules = append(p.AllowedEgressRules, EgressPolicy{
				Host:     rule.Host,
				Port:     rule.Port,
				Protocol: rule.Protocol,
			})
		}
	}

	if len(net.Deny) > 0 {
		denied := make(map[string]bool, len(net.Deny))
		for _, h := range net.Deny {
			denied[h] = true
		}
		filtered := make([]string, 0, len(p.AllowedHosts))
		for _, h := range p.AllowedHosts {
			if !denied[h] {
				filtered = append(filtered, h)
			}
		}
		p.AllowedHosts = filtered

		filteredRules := make([]EgressPolicy, 0, len(p.AllowedEgressRules))
		for _, r := range p.AllowedEgressRules {
			if !denied[r.Host] {
				filteredRules = append(filteredRules, r)
			}
		}
		p.AllowedEgressRules = filteredRules
	}
}

// resolveShell maps shell capability declarations to the policy.
func resolveShell(p *ContainerPolicy, shell *config.ShellCaps) {
	if shell == nil {
		return
	}

	if len(shell.Commands) > 0 {
		p.ShellAllowed = true
		for _, cmd := range shell.Commands {
			p.AllowedCommands = append(p.AllowedCommands, cmd.Binary)
		}
	}
}

// resolveGit maps git capability declarations to the policy.
func resolveGit(p *ContainerPolicy, git *config.GitCaps) {
	if git == nil {
		return
	}

	p.GitAllowed = true

	if git.Branches == nil {
		return
	}

	if len(git.Branches.Push) > 0 {
		p.GitPushAllowed = true
		p.GitPushBranches = append(p.GitPushBranches, git.Branches.Push...)
	}

	if len(git.Branches.Deny) > 0 {
		p.GitDenyBranches = append(p.GitDenyBranches, git.Branches.Deny...)
	}
}

// ResolveSecrets builds SecretACL entries by cross-referencing the declared
// secrets with MCP tool configurations. For each unique secret path, it
// collects all MCP tools that reference it (via the tool's Secrets field) and
// merges any AllowedTools declared on the SecretConfig itself.
//
// The TTL string from SecretConfig (e.g. "1h", "30m") is parsed via
// time.ParseDuration and converted to seconds. Unparseable TTLs are treated
// as zero (no expiry).
func ResolveSecrets(secrets map[string]config.SecretConfig, tools *config.ToolsConfig) []SecretACL {
	if len(secrets) == 0 {
		return nil
	}

	// Map secret key -> set of tool names that reference it.
	toolsBySecret := make(map[string]map[string]bool)

	// Collect tool references from MCP tool configs.
	if tools != nil {
		for toolName, mcp := range tools.MCP {
			for _, secretKey := range mcp.Secrets {
				if _, ok := secrets[secretKey]; !ok {
					continue // skip references to undefined secrets
				}
				if toolsBySecret[secretKey] == nil {
					toolsBySecret[secretKey] = make(map[string]bool)
				}
				toolsBySecret[secretKey][toolName] = true
			}
		}
	}

	// Merge AllowedTools from SecretConfig itself.
	for secretKey, sc := range secrets {
		for _, toolName := range sc.AllowedTools {
			if toolsBySecret[secretKey] == nil {
				toolsBySecret[secretKey] = make(map[string]bool)
			}
			toolsBySecret[secretKey][toolName] = true
		}
	}

	// Build SecretACL entries for each secret that has a path.
	var acls []SecretACL
	for secretKey, sc := range secrets {
		if sc.Path == "" {
			continue
		}

		var ttlSec uint64
		if sc.TTL != "" {
			if d, err := time.ParseDuration(sc.TTL); err == nil && d > 0 {
				ttlSec = uint64(d.Seconds())
			}
		}

		var allowed []string
		if ts := toolsBySecret[secretKey]; len(ts) > 0 {
			allowed = make([]string, 0, len(ts))
			for t := range ts {
				allowed = append(allowed, t)
			}
			sort.Strings(allowed)
		}

		acls = append(acls, SecretACL{
			Path:         sc.Path,
			AllowedTools: allowed,
			TTLSeconds:   ttlSec,
		})
	}

	// Sort by path for deterministic output.
	sort.Slice(acls, func(i, j int) bool {
		return acls[i].Path < acls[j].Path
	})

	return acls
}
