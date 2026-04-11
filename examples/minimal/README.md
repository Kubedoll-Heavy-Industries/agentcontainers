# Minimal Agent Container

The simplest working `agentcontainer.json` configuration. Good starting point for any project.

## What This Example Does

- Uses a standard Ubuntu devcontainer base image
- Allows filesystem read/write within `/workspace/` (denies `.env` and `.git/config`)
- Permits npm and git commands
- Allows HTTPS egress to npm registry and GitHub API only
- Prompts the user for any capability escalation
- Session timeout of 4 hours

## Quick Start

```bash
# Copy the config into your project
cp agentcontainer.json /path/to/your-project/

# Run the agent container
ac run /path/to/your-project
```

## Customization

**Change the base image** — replace the `image` field with any OCI image:

```jsonc
"image": "mcr.microsoft.com/devcontainers/python:3.12"
```

**Add network egress** — append to the `egress` array:

```jsonc
{ "host": "pypi.org", "port": 443 }
```

**Allow more shell commands** — append strings or objects to `commands`:

```jsonc
"python -m pytest",
{ "binary": "make", "subcommands": ["build", "test"] }
```

**Lock down further** — set `escalation` to `"deny"` to block all capability requests without prompting.
