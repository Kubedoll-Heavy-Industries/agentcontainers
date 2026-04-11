---
title: Secrets Management
description: Configure and manage secrets for agent containers using Vault, 1Password, Infisical, and other providers.
---

agentcontainers provides a pluggable secrets system that injects credentials into agent containers via tmpfs mounts at `/run/secrets/`. All secrets are short-lived, scoped to specific tools, and rotated automatically.

## How it works

1. You declare secrets in `agentcontainer.json` under `agent.secrets`.
2. At session start, the **Secrets Manager** resolves each secret through its provider.
3. Resolved values are written to `/run/secrets/<name>` (tmpfs, mode 0400).
4. The container never contacts secret providers directly.
5. TTL-based rotation refreshes secrets without container restart.

## Quickstart

Add a `secrets` block to your `agentcontainer.json`:

```jsonc
{
  "image": "node:22",
  "agent": {
    "secrets": {
      "GITHUB_TOKEN": {
        "provider": "oidc",
        "audience": "https://github.com",
        "ttl": "1h"
      },
      "DB_PASSWORD": {
        "provider": "vault",
        "path": "secret/data/myapp/db",
        "key": "password",
        "ttl": "15m"
      }
    }
  }
}
```

Inside the container, read secrets from files:

```bash
cat /run/secrets/GITHUB_TOKEN
cat /run/secrets/DB_PASSWORD
```

## URI scheme syntax

Instead of structured config, you can use URI scheme shorthand in the `provider` field. The runtime detects URI prefixes and auto-registers the correct provider.

| URI Scheme | Provider | Example |
|---|---|---|
| `op://` | 1Password | `op://vault-name/item-name/field-name` |
| `vault://` | HashiCorp Vault / OpenBao | `vault://secret/data/myapp/config#api_key` |
| `infisical://` | Infisical | `infisical://project-id/production/DATABASE_URL` |
| `env://` | Environment variable | `env://MY_API_KEY` |
| `oidc://` | OIDC token | `oidc://api.example.com` |

URI scheme example:

```jsonc
{
  "agent": {
    "secrets": {
      "API_KEY": {
        "provider": "op://Engineering/api-credentials/api-key"
      },
      "DB_URL": {
        "provider": "vault://secret/data/myapp/db#connection_string"
      }
    }
  }
}
```

## Providers

### OIDC (built-in)

The OIDC provider is the zero-infrastructure option. A lightweight OIDC issuer is built directly into the `ac` runtime and mints short-lived JWTs. Register it as a trusted OIDC provider with AWS STS, GCP Workload Identity, or GitHub Apps.

```jsonc
{
  "GITHUB_TOKEN": {
    "provider": "oidc",
    "audience": "https://github.com",
    "ttl": "1h",
    "scope": ["repo:read", "actions:read"]
  }
}
```

No Vault cluster, no SPIRE deployment required.

### Environment variables

Pass host environment variables into the container. Useful for local development or CI where secrets are already in the environment.

```jsonc
{
  "CI_TOKEN": {
    "provider": "env",
    "path": "CI_TOKEN"
  }
}
```

Or with URI syntax: `"provider": "env://CI_TOKEN"`

### HashiCorp Vault / OpenBao

Reads secrets from a Vault or OpenBao KV v2 engine. Requires `VAULT_ADDR` and `VAULT_TOKEN` (or other Vault auth) on the host.

```jsonc
{
  "DB_PASSWORD": {
    "provider": "vault",
    "path": "secret/data/myapp/db",
    "key": "password",
    "role": "myapp-reader",
    "ttl": "15m"
  }
}
```

URI syntax: `"provider": "vault://secret/data/myapp/db#password"`

**Required environment variables:**

| Variable | Description |
|---|---|
| `VAULT_ADDR` | Vault server address (e.g., `https://vault.example.com:8200`) |
| `VAULT_TOKEN` | Authentication token (or use `VAULT_ROLE_ID` / `VAULT_SECRET_ID` for AppRole) |
| `VAULT_NAMESPACE` | (Optional) Vault Enterprise namespace |

### 1Password

Reads secrets from 1Password using the `op://` URI scheme. Requires the 1Password CLI (`op`) or 1Password Connect server.

```jsonc
{
  "API_KEY": {
    "provider": "1password",
    "path": "op://Engineering/api-credentials/api-key"
  }
}
```

URI syntax: `"provider": "op://Engineering/api-credentials/api-key"`

The URI format is `op://vault/item[/field]`:
- **vault**: The 1Password vault name
- **item**: The item name within the vault
- **field**: (Optional) Specific field name. Defaults to `password`.

**Required environment variables:**

| Variable | Description |
|---|---|
| `OP_SERVICE_ACCOUNT_TOKEN` | 1Password Service Account token (recommended for CI) |

Or authenticate interactively via `op signin`.

### Infisical

Reads secrets from Infisical's universal secrets manager.

```jsonc
{
  "DATABASE_URL": {
    "provider": "infisical",
    "path": "infisical://proj-abc123/production/DATABASE_URL"
  }
}
```

URI syntax: `"provider": "infisical://proj-abc123/production/DATABASE_URL"`

The URI format is `infisical://projectID/environment/secretName`:
- **projectID**: The Infisical project identifier
- **environment**: Environment slug (e.g., `production`, `staging`, `dev`)
- **secretName**: The secret key name

**Required environment variables:**

| Variable | Description |
|---|---|
| `INFISICAL_TOKEN` | Infisical API token or Universal Auth token |
| `INFISICAL_API_URL` | (Optional) Self-hosted Infisical API URL |

## Per-tool scoping

Secrets can be scoped to specific MCP servers using `allowedTools`. A compromised MCP server cannot read secrets it was not granted.

```jsonc
{
  "agent": {
    "secrets": {
      "GITHUB_TOKEN": {
        "provider": "oidc",
        "audience": "https://github.com",
        "allowedTools": ["github-mcp"]
      },
      "DB_PASSWORD": {
        "provider": "vault",
        "path": "secret/data/myapp/db",
        "key": "password",
        "allowedTools": ["db-query"]
      }
    },
    "tools": {
      "mcp": {
        "github-mcp": {
          "image": "ghcr.io/myorg/github-mcp:v1",
          "secrets": ["GITHUB_TOKEN"]
        },
        "db-query": {
          "image": "ghcr.io/myorg/db-mcp:v1",
          "secrets": ["DB_PASSWORD"]
        }
      }
    }
  }
}
```

Each MCP server's namespace mounts only the tmpfs entries it declared.

## On-demand resolution with `ac exec`

The `ac exec` command supports resolving secrets on the fly using the `--env` flag with URI syntax:

```bash
ac exec mycontainer --env "API_KEY=op://Engineering/api-creds/key" -- curl https://api.example.com
```

The runtime detects the URI scheme, resolves the secret through the appropriate provider, and injects it as an environment variable for that single exec invocation. The secret is never written to disk.

## TTL and rotation

All secrets support TTL-based expiration and automatic rotation:

```jsonc
{
  "AWS_SESSION": {
    "provider": "oidc",
    "audience": "sts.amazonaws.com",
    "ttl": "15m",
    "rotation": "auto"
  }
}
```

- The Secrets Manager watches TTLs and writes refreshed values to the same path.
- Rotation uses atomic write (write to temp file, then rename) so readers never see partial data.
- If rotation fails, the stale credential remains until TTL expiry (never extended). Failure is logged and surfaced to the user.
- If a provider fails at session start, the session does not launch (fail-closed).

## Security properties

- **No ambient credentials.** The container never has access to host credential stores, SSH keys, or browser cookies.
- **Short-lived everything.** Every credential has a TTL. OIDC JWTs max at 1 hour. AWS STS credentials cap at 15 minutes.
- **Per-tool isolation.** Each MCP server sees only its declared secrets.
- **Fail-closed.** Provider failures at startup prevent the session from launching.
- **Kernel-level enforcement.** The BPF LSM `file_open` hook enforces per-cgroup credential ACLs. Even if a process escapes its namespace, it cannot read another container's secrets.
