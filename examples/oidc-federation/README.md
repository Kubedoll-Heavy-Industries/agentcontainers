# OIDC Federation

Demonstrates zero-infrastructure credential federation using the `ac` runtime's built-in OIDC issuer. No Vault, no SPIRE, no external secrets manager required. The OIDC issuer mints JWTs that AWS, GCP, and GitHub consume via their native OIDC federation support.

## Prerequisites

- `ac` CLI
- Cloud provider accounts with OIDC federation configured (see setup below)

## Quick Start

```bash
# 1. Set up cloud provider OIDC trust (one-time, see below)

# 2. Run the agent container
ac run --config agentcontainer.json .
```

## Secrets in This Example

| Secret | Provider | Audience | TTL | Description |
|--------|----------|----------|-----|-------------|
| `AWS_SESSION` | OIDC | `sts.amazonaws.com` | 15m | AWS STS temporary credentials |
| `GCP_TOKEN` | OIDC | GCP Workload Identity | 1h | GCP access token |
| `GITHUB_TOKEN` | OIDC | `github.com` | 1h | GitHub installation token |

## AWS Setup (One-Time)

Register the `ac` OIDC issuer as a trusted identity provider in AWS:

```bash
# 1. Create OIDC Identity Provider in AWS IAM
aws iam create-open-id-connect-provider \
  --url "https://ac.your-org.com" \
  --client-id-list "sts.amazonaws.com" \
  --thumbprint-list "<your-issuer-tls-thumbprint>"

# 2. Create IAM role with trust policy
cat > trust-policy.json << 'POLICY'
{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Principal": {
      "Federated": "arn:aws:iam::123456789012:oidc-provider/ac.your-org.com"
    },
    "Action": "sts:AssumeRoleWithWebIdentity",
    "Condition": {
      "StringEquals": {
        "ac.your-org.com:aud": "sts.amazonaws.com"
      }
    }
  }]
}
POLICY

aws iam create-role \
  --role-name agent-s3-readonly \
  --assume-role-policy-document file://trust-policy.json

# 3. Attach permissions
aws iam attach-role-policy \
  --role-name agent-s3-readonly \
  --policy-arn arn:aws:iam::aws:policy/AmazonS3ReadOnlyAccess
```

## GCP Setup (One-Time)

Register the `ac` OIDC issuer with GCP Workload Identity Federation:

```bash
# 1. Create Workload Identity Pool
gcloud iam workload-identity-pools create agent-pool \
  --location="global" \
  --display-name="Agent Container Pool"

# 2. Add OIDC provider
gcloud iam workload-identity-pools providers create-oidc ac-provider \
  --location="global" \
  --workload-identity-pool="agent-pool" \
  --issuer-uri="https://ac.your-org.com" \
  --allowed-audiences="//iam.googleapis.com/projects/123456789/locations/global/workloadIdentityPools/agent-pool/providers/ac-provider"

# 3. Grant service account impersonation
gcloud iam service-accounts add-iam-policy-binding \
  agent-sa@my-project.iam.gserviceaccount.com \
  --role="roles/iam.workloadIdentityUser" \
  --member="principalSet://iam.googleapis.com/projects/123456789/locations/global/workloadIdentityPools/agent-pool/*"
```

## How It Works

1. `agentcontainer run` starts the built-in OIDC issuer (HTTP server on localhost)
2. The issuer serves `/.well-known/openid-configuration` and `/jwks` endpoints
3. For each OIDC secret, the Secrets Manager:
   - Mints a JWT signed with an ephemeral key (claims include `aud`, `sub`, `iss`)
   - Calls the cloud provider's token exchange endpoint (e.g., AWS STS `AssumeRoleWithWebIdentity`)
   - Receives temporary credentials and writes them to `/run/secrets/<NAME>`
4. Cloud providers validate the JWT by fetching the JWKS from the issuer URL
5. Rotation happens automatically before TTL expiry

## OIDC Issuer Hosting

The cloud provider must be able to reach the OIDC issuer's JWKS endpoint. Options:

| Pattern | Description |
|---------|-------------|
| **Central issuer** | Org hosts a shared OIDC issuer at a stable URL (recommended for enterprise) |
| **Cloudflare Tunnel** | Expose local issuer via tunnel (good for development) |
| **CI-native** | In GitHub Actions, delegate to the built-in OIDC issuer |

## Production Notes

- AWS STS credentials are capped at 15 minutes for minimal blast radius
- Ephemeral signing keys are generated per-session and zeroed on exit
- The OIDC issuer URL must be stable — changing it requires re-registering with all cloud providers
- Use the central issuer pattern for teams to avoid per-developer URL management
