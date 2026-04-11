---
title: Configuration
description: Full reference for the agentcontainer.json configuration file.
---

`agentcontainer.json` is the central configuration file. It is a strict superset of `devcontainer.json` -- any valid devcontainer is a valid agentcontainer with default-deny agent capabilities.

## Config resolution order

The runtime searches for configuration in this order:

1. `agentcontainer.json` (workspace root)
2. `.devcontainer/agentcontainer.json`
3. `.devcontainer/devcontainer.json` (default-deny)

## Base fields

These are standard devcontainer fields:

```jsonc
{
  "name": "my-agent",
  "image": "node:22",
  "build": {
    "dockerfile": "Dockerfile",
    "context": ".",
    "args": { "NODE_VERSION": "22" }
  },
  "features": {},
  "mounts": []
}
```

## The `agent` key

The `agent` key is the agentcontainer extension. It adds capabilities, tools, secrets, policy, provenance, and enforcer configuration.

### Capabilities

```jsonc
{
  "agent": {
    "capabilities": {
      "network": {
        "allow": ["api.github.com:443", "registry.npmjs.org:443"]
      },
      "filesystem": {
        "read": ["/workspace/**", "/usr/**"],
        "write": ["/workspace/**", "/tmp/**"],
        "deny": ["/etc/shadow"]
      },
      "shell": {
        "allow": ["git", "npm", "node", "python3"],
        "deny": ["curl", "wget", "sudo"]
      },
      "git": {
        "allow": ["push", "pull", "commit"],
        "branches": ["main", "feature/*"]
      }
    }
  }
}
```

### Tools

MCP servers and skills:

```jsonc
{
  "agent": {
    "tools": {
      "mcp": {
        "github-mcp": {
          "image": "ghcr.io/myorg/github-mcp:v1",
          "capabilities": ["network"],
          "secrets": ["GITHUB_TOKEN"]
        }
      },
      "skills": {
        "code-review": {
          "artifact": "ghcr.io/myorg/code-review-skill:v1",
          "trust": "sigstore",
          "requires": ["git", "filesystem"]
        }
      }
    }
  }
}
```

### Secrets

See the [Secrets Management guide](/guides/secrets/) for full details.

```jsonc
{
  "agent": {
    "secrets": {
      "GITHUB_TOKEN": {
        "provider": "oidc",
        "audience": "https://github.com",
        "ttl": "1h",
        "allowedTools": ["github-mcp"]
      },
      "DB_PASSWORD": {
        "provider": "vault://secret/data/myapp/db#password"
      }
    }
  }
}
```

### Policy

```jsonc
{
  "agent": {
    "policy": {
      "escalation": "prompt",
      "auditLog": true,
      "sessionTimeout": "8h",
      "maxConcurrentTools": 5,
      "onCapabilityViolation": "block"
    }
  }
}
```

| Field | Description |
|---|---|
| `escalation` | How capability escalation is handled: `"prompt"` (ask user), `"deny"` (block), `"allow"` (auto-approve) |
| `auditLog` | Enable audit logging of enforcement events |
| `sessionTimeout` | Maximum session duration |
| `maxConcurrentTools` | Limit on simultaneously running MCP servers |
| `onCapabilityViolation` | Action on violation: `"block"`, `"log"`, `"prompt"` |

### Provenance

```jsonc
{
  "agent": {
    "provenance": {
      "require": {
        "signatures": true,
        "sbom": true,
        "slsaLevel": 2,
        "trustedBuilders": ["github-actions"],
        "trustedRegistries": ["ghcr.io/myorg/*"]
      }
    }
  }
}
```

### Org policy

Reference an org policy stored as an OCI artifact:

```jsonc
{
  "agent": {
    "orgPolicy": "ghcr.io/myorg/policy:latest"
  }
}
```

See the [Organization Policy guide](/guides/org-policy/) for details.

### Enforcer

Configure the BPF enforcer sidecar:

```jsonc
{
  "agent": {
    "enforcer": {
      "image": "ghcr.io/kubedoll-heavy-industries/ac-enforcer:latest",
      "required": true
    }
  }
}
```

| Field | Description |
|---|---|
| `image` | OCI reference for the ac-enforcer container |
| `required` | If `true` (default), `ac run` fails if the sidecar cannot start. Set to `false` only for local development. |
| `addr` | gRPC address of a pre-existing sidecar (skip auto-start) |

## Complete example

```jsonc
{
  "name": "my-secure-agent",
  "image": "node:22",
  "agent": {
    "capabilities": {
      "network": {
        "allow": ["api.github.com:443", "registry.npmjs.org:443"]
      },
      "filesystem": {
        "read": ["/workspace/**"],
        "write": ["/workspace/**", "/tmp/**"]
      },
      "shell": {
        "allow": ["git", "npm", "node"]
      }
    },
    "tools": {
      "mcp": {
        "github-mcp": {
          "image": "ghcr.io/myorg/github-mcp:v1",
          "secrets": ["GITHUB_TOKEN"]
        }
      }
    },
    "secrets": {
      "GITHUB_TOKEN": {
        "provider": "oidc",
        "audience": "https://github.com",
        "ttl": "1h",
        "allowedTools": ["github-mcp"]
      }
    },
    "policy": {
      "escalation": "prompt",
      "auditLog": true,
      "sessionTimeout": "8h",
      "onCapabilityViolation": "block"
    },
    "provenance": {
      "require": {
        "signatures": true,
        "sbom": true,
        "slsaLevel": 2
      }
    },
    "orgPolicy": "ghcr.io/myorg/policy:latest",
    "enforcer": {
      "required": true
    }
  }
}
```
