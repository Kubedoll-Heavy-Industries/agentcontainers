import { describe, it, expect, beforeAll, afterAll } from "vitest";
import { GenericContainer, Wait, type StartedTestContainer } from "testcontainers";
import { execSync } from "node:child_process";
import { mkdtempSync, writeFileSync, rmSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";

const ROOT = join(import.meta.dirname, "..", "..");
const AC_BIN = join(ROOT, "tmp", "ac");
const ENFORCER_IMAGE = process.env.AC_ENFORCER_IMAGE ?? "ac-enforcer:test";

/** PUT a KV v2 secret into OpenBao/Vault via the HTTP API. */
async function putSecret(
  addr: string,
  token: string,
  path: string,
  data: Record<string, string>,
): Promise<void> {
  const res = await fetch(`${addr}/v1/secret/data/${path}`, {
    method: "POST",
    headers: {
      "X-Vault-Token": token,
      "Content-Type": "application/json",
    },
    body: JSON.stringify({ data }),
  });
  if (!res.ok) {
    const body = await res.text();
    throw new Error(`PUT secret ${path}: HTTP ${res.status}: ${body}`);
  }
}

/** Run ac and parse the container ID from output. */
function acRun(configPath: string, workdir: string, env: Record<string, string>): string {
  const result = execSync(
    `${AC_BIN} run --detach --config ${configPath} --runtime docker`,
    {
      cwd: workdir,
      env: { ...process.env, ...env },
      encoding: "utf-8",
      timeout: 120_000,
    },
  );
  const match = result.match(/Container:\s+(\S+)/);
  if (!match) throw new Error(`Failed to parse container ID from: ${result}`);
  return match[1];
}

/** Stop an ac container, ignoring errors. */
function acStop(containerId: string, workdir: string) {
  try {
    execSync(`${AC_BIN} stop ${containerId}`, {
      cwd: workdir,
      stdio: "pipe",
      timeout: 30_000,
    });
  } catch {
    // Best effort — container may already be stopped.
  }
}

describe("secrets: vault provider with OpenBao + enforcer", () => {
  let bao: StartedTestContainer;
  let baoAddr: string;
  let workdir: string;
  const rootToken = "root-token-for-test";

  beforeAll(async () => {
    // 1. Build the agentcontainer binary.
    execSync("go build -o tmp/agentcontainer ./cmd/agentcontainer", { cwd: ROOT, stdio: "pipe" });

    // 2. Verify enforcer image exists (built externally).
    try {
      execSync(`docker image inspect ${ENFORCER_IMAGE}`, { stdio: "pipe" });
    } catch {
      throw new Error(
        `Enforcer image ${ENFORCER_IMAGE} not found. Build it first:\n` +
        `  docker build -t ac-enforcer:test ./enforcer`,
      );
    }

    // 3. Start OpenBao in dev mode.
    bao = await new GenericContainer("quay.io/openbao/openbao:latest")
      .withExposedPorts(8200)
      .withEnvironment({
        BAO_DEV_ROOT_TOKEN_ID: rootToken,
        BAO_DEV_LISTEN_ADDRESS: "0.0.0.0:8200",
      })
      .withCommand(["server", "-dev"])
      .withWaitStrategy(Wait.forHttp("/v1/sys/health", 8200).forStatusCode(200))
      .start();

    baoAddr = `http://${bao.getHost()}:${bao.getMappedPort(8200)}`;

    // 4. Write test secrets.
    await putSecret(baoAddr, rootToken, "myapp/config", {
      api_key: "sk-test-openbao-12345",
      db_password: "hunter2",
    });

    // 5. Create a temp workspace with agentcontainer.json.
    workdir = mkdtempSync(join(tmpdir(), "ac-vault-test-"));
    writeFileSync(
      join(workdir, "agentcontainer.json"),
      JSON.stringify({
        image: "alpine:3.20",
        agent: {
          enforcer: { image: ENFORCER_IMAGE },
          secrets: {
            "api-key": {
              provider: "vault",
              path: "myapp/config",
              key: "api_key",
            },
            "db-pass": {
              provider: "vault",
              path: "myapp/config",
              key: "db_password",
            },
          },
        },
      }),
    );
  });

  afterAll(async () => {
    if (bao) await bao.stop();
    if (workdir) rmSync(workdir, { recursive: true, force: true });
  });

  it("resolves vault secrets and injects them into /run/secrets/", async () => {
    const containerId = acRun(
      join(workdir, "agentcontainer.json"),
      workdir,
      { VAULT_ADDR: baoAddr, VAULT_TOKEN: rootToken },
    );

    try {
      const apiKey = execSync(
        `docker exec ${containerId} cat /run/secrets/api-key`,
        { encoding: "utf-8" },
      ).trim();

      const dbPass = execSync(
        `docker exec ${containerId} cat /run/secrets/db-pass`,
        { encoding: "utf-8" },
      ).trim();

      expect(apiKey).toBe("sk-test-openbao-12345");
      expect(dbPass).toBe("hunter2");

      // Verify permissions.
      const perms = execSync(
        `docker exec ${containerId} stat -c '%a' /run/secrets/api-key`,
        { encoding: "utf-8" },
      ).trim();
      expect(perms).toBe("400");
    } finally {
      acStop(containerId, workdir);
    }
  });

  it("rejects secrets with invalid vault path", async () => {
    const badWorkdir = mkdtempSync(join(tmpdir(), "ac-vault-bad-"));
    writeFileSync(
      join(badWorkdir, "agentcontainer.json"),
      JSON.stringify({
        image: "alpine:3.20",
        agent: {
          enforcer: { image: ENFORCER_IMAGE },
          secrets: {
            "missing-secret": {
              provider: "vault",
              path: "nonexistent/path",
              key: "nope",
            },
          },
        },
      }),
    );

    try {
      execSync(
        `${AC_BIN} run --detach --config ${join(badWorkdir, "agentcontainer.json")} --runtime docker`,
        {
          cwd: badWorkdir,
          env: { ...process.env, VAULT_ADDR: baoAddr, VAULT_TOKEN: rootToken },
          encoding: "utf-8",
          timeout: 60_000,
        },
      );
      expect.unreachable("ac run should have failed for nonexistent secret");
    } catch (err: any) {
      expect(err.stderr || err.message).toContain("vault");
    } finally {
      rmSync(badWorkdir, { recursive: true, force: true });
    }
  });

  it("resolves vault secrets via URI scheme", async () => {
    const uriWorkdir = mkdtempSync(join(tmpdir(), "ac-vault-uri-"));
    writeFileSync(
      join(uriWorkdir, "agentcontainer.json"),
      JSON.stringify({
        image: "alpine:3.20",
        agent: {
          enforcer: { image: ENFORCER_IMAGE },
          secrets: {
            "uri-secret": {
              provider: "vault://myapp/config#api_key",
            },
          },
        },
      }),
    );

    try {
      const containerId = acRun(
        join(uriWorkdir, "agentcontainer.json"),
        uriWorkdir,
        { VAULT_ADDR: baoAddr, VAULT_TOKEN: rootToken },
      );

      try {
        const value = execSync(
          `docker exec ${containerId} cat /run/secrets/uri-secret`,
          { encoding: "utf-8" },
        ).trim();

        expect(value).toBe("sk-test-openbao-12345");
      } finally {
        acStop(containerId, uriWorkdir);
      }
    } finally {
      rmSync(uriWorkdir, { recursive: true, force: true });
    }
  });
});
