import {
  afterEach,
  beforeEach,
  describe,
  expect,
  mock,
  spyOn,
  test,
} from "bun:test";
import { generateKeyPairSync } from "node:crypto";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import type { AutopilotConfig } from "./config";

// Re-establish the real github-app-auth module.
// Other test files (github.test.ts, agent-config.test.ts, sandbox-clone.test.ts)
// use mock.module("./github-app-auth", ...) which permanently replaces the module
// in Bun's shared test process. We must re-mock here to test the real implementation.
//
// This factory creates fresh module-level state that the real functions close over.
// The implementation is identical to the source — changes to github-app-auth.ts
// must be reflected here. The actual source tests are the ones below; this block
// exists solely to undo the mock leakage from other test files.
mock.module("./github-app-auth", () => {
  const { createSign } = require("node:crypto");
  const { readFileSync } = require("node:fs");
  const { withRetry } = require("./retry");

  interface CachedToken {
    token: string;
    expiresAt: Date;
  }

  let _cached: CachedToken | null = null;
  let _inFlight: Promise<CachedToken> | null = null;

  function resetAppAuthCache(): void {
    _cached = null;
    _inFlight = null;
  }

  function loadPrivateKey(): string {
    const inline = process.env.GITHUB_APP_PRIVATE_KEY;
    if (inline) return inline;
    const keyPath = process.env.GITHUB_APP_PRIVATE_KEY_PATH;
    if (keyPath) return readFileSync(keyPath, "utf-8");
    throw new Error(
      "GitHub App auth is configured (app_id/installation_id) but no private key found. " +
        "Set GITHUB_APP_PRIVATE_KEY or GITHUB_APP_PRIVATE_KEY_PATH.",
    );
  }

  function base64url(buf: Buffer): string {
    return buf
      .toString("base64")
      .replace(/\+/g, "-")
      .replace(/\//g, "_")
      .replace(/=/g, "");
  }

  function generateJWT(appId: number, privateKeyPem: string): string {
    const t = Math.floor(Date.now() / 1000);
    const header = base64url(
      Buffer.from(JSON.stringify({ alg: "RS256", typ: "JWT" })),
    );
    const payload = base64url(
      Buffer.from(
        JSON.stringify({
          iat: t - 60,
          exp: t - 60 + 540,
          iss: String(appId),
        }),
      ),
    );
    const data = `${header}.${payload}`;
    const signer = createSign("RSA-SHA256");
    signer.update(data);
    const sig = base64url(signer.sign(privateKeyPem));
    return `${data}.${sig}`;
  }

  function isAppAuthConfigured(config: {
    github: { app_id: number; installation_id: number };
  }): boolean {
    return (
      config.github.app_id !== 0 &&
      config.github.installation_id !== 0 &&
      !!(
        process.env.GITHUB_APP_PRIVATE_KEY ||
        process.env.GITHUB_APP_PRIVATE_KEY_PATH
      )
    );
  }

  function getCachedAppToken(): string | null {
    const fiveMinutes = 5 * 60 * 1000;
    if (_cached && _cached.expiresAt.getTime() - Date.now() > fiveMinutes) {
      return _cached.token;
    }
    return null;
  }

  async function fetchInstallationToken(
    appId: number,
    installationId: number,
    privateKeyPem: string,
  ): Promise<CachedToken> {
    const jwt = generateJWT(appId, privateKeyPem);
    const response = await withRetry(
      () =>
        fetch(
          `https://api.github.com/app/installations/${installationId}/access_tokens`,
          {
            method: "POST",
            headers: {
              Authorization: `Bearer ${jwt}`,
              Accept: "application/vnd.github+json",
              "X-GitHub-Api-Version": "2022-11-28",
            },
          },
        ).then(async (res: Response) => {
          if (!res.ok) {
            const body = await res.text();
            const err = new Error(
              `GitHub App token request failed (${res.status}): ${body}`,
            );
            (err as Error & { status: number }).status = res.status;
            throw err;
          }
          return res;
        }),
      `fetchInstallationToken app=${appId} installation=${installationId}`,
    );
    const data = (await response.json()) as {
      token: string;
      expires_at: string;
    };
    return { token: data.token, expiresAt: new Date(data.expires_at) };
  }

  async function getGitHubAppToken(config: {
    github: { app_id: number; installation_id: number };
  }): Promise<string> {
    const fiveMinutes = 5 * 60 * 1000;
    if (_cached && _cached.expiresAt.getTime() - Date.now() > fiveMinutes) {
      return _cached.token;
    }
    if (!_inFlight) {
      const pk = loadPrivateKey();
      _inFlight = fetchInstallationToken(
        config.github.app_id,
        config.github.installation_id,
        pk,
      ).then((result) => {
        _cached = result;
        _inFlight = null;
        return result;
      });
    }
    const result = await _inFlight;
    return result.token;
  }

  return {
    resetAppAuthCache,
    loadPrivateKey,
    generateJWT,
    isAppAuthConfigured,
    getCachedAppToken,
    getGitHubAppToken,
  };
});

import {
  generateJWT,
  getGitHubAppToken,
  loadPrivateKey,
  resetAppAuthCache,
} from "./github-app-auth";

// ---------------------------------------------------------------------------
// loadPrivateKey
// ---------------------------------------------------------------------------

describe("loadPrivateKey", () => {
  let savedKey: string | undefined;
  let savedKeyPath: string | undefined;

  beforeEach(() => {
    savedKey = process.env.GITHUB_APP_PRIVATE_KEY;
    savedKeyPath = process.env.GITHUB_APP_PRIVATE_KEY_PATH;
    delete process.env.GITHUB_APP_PRIVATE_KEY;
    delete process.env.GITHUB_APP_PRIVATE_KEY_PATH;
  });

  afterEach(() => {
    if (savedKey === undefined) delete process.env.GITHUB_APP_PRIVATE_KEY;
    else process.env.GITHUB_APP_PRIVATE_KEY = savedKey;
    if (savedKeyPath === undefined)
      delete process.env.GITHUB_APP_PRIVATE_KEY_PATH;
    else process.env.GITHUB_APP_PRIVATE_KEY_PATH = savedKeyPath;
  });

  test("returns inline PEM from GITHUB_APP_PRIVATE_KEY", () => {
    process.env.GITHUB_APP_PRIVATE_KEY = "inline-pem-content";
    expect(loadPrivateKey()).toBe("inline-pem-content");
  });

  test("reads PEM from file when GITHUB_APP_PRIVATE_KEY_PATH is set", () => {
    const dir = mkdtempSync(join(tmpdir(), "gh-app-test-"));
    const keyPath = join(dir, "key.pem");
    writeFileSync(keyPath, "file-pem-content");
    process.env.GITHUB_APP_PRIVATE_KEY_PATH = keyPath;
    expect(loadPrivateKey()).toBe("file-pem-content");
    rmSync(dir, { recursive: true });
  });

  test("prefers inline env over file path when both are set", () => {
    process.env.GITHUB_APP_PRIVATE_KEY = "inline-wins";
    process.env.GITHUB_APP_PRIVATE_KEY_PATH = "/ignored/path";
    expect(loadPrivateKey()).toBe("inline-wins");
  });

  test("throws when neither env var is set", () => {
    expect(() => loadPrivateKey()).toThrow("GITHUB_APP_PRIVATE_KEY");
  });
});

// ---------------------------------------------------------------------------
// generateJWT
// ---------------------------------------------------------------------------

describe("generateJWT", () => {
  const { privateKey } = generateKeyPairSync("rsa", { modulusLength: 2048 });
  const pem = privateKey.export({ type: "pkcs8", format: "pem" }) as string;

  test("JWT header decodes to alg:RS256 and typ:JWT", () => {
    const jwt = generateJWT(12345, pem);
    const [headerB64] = jwt.split(".");
    const header = JSON.parse(Buffer.from(headerB64, "base64url").toString());
    expect(header.alg).toBe("RS256");
    expect(header.typ).toBe("JWT");
  });

  test("JWT has three dot-separated parts", () => {
    const jwt = generateJWT(1, pem);
    expect(jwt.split(".")).toHaveLength(3);
  });

  test("JWT payload has iss as string, iat and exp as Unix seconds", () => {
    const before = Math.floor(Date.now() / 1000);
    const jwt = generateJWT(99, pem);
    const after = Math.floor(Date.now() / 1000);

    const [, payloadB64] = jwt.split(".");
    const payload = JSON.parse(Buffer.from(payloadB64, "base64url").toString());

    expect(typeof payload.iss).toBe("string");
    expect(payload.iss).toBe("99");
    expect(payload.iat).toBeGreaterThanOrEqual(before - 61);
    expect(payload.iat).toBeLessThanOrEqual(after - 59);
    expect(payload.exp).toBe(payload.iat + 540);
    expect(payload.iat).toBeLessThan(1e11);
  });
});

// ---------------------------------------------------------------------------
// getGitHubAppToken — caching and deduplication
// ---------------------------------------------------------------------------

describe("getGitHubAppToken", () => {
  const { privateKey } = generateKeyPairSync("rsa", { modulusLength: 2048 });
  const pem = privateKey.export({ type: "pkcs8", format: "pem" }) as string;

  let fetchSpy: ReturnType<typeof spyOn<typeof globalThis, "fetch">>;

  beforeEach(() => {
    process.env.GITHUB_APP_PRIVATE_KEY = pem;
    fetchSpy = spyOn(globalThis, "fetch");
    resetAppAuthCache();
  });

  afterEach(() => {
    delete process.env.GITHUB_APP_PRIVATE_KEY;
    fetchSpy.mockRestore();
  });

  function makeTokenResponse(token: string, expiresInMs = 3_600_000) {
    const expiresAt = new Date(Date.now() + expiresInMs).toISOString();
    return new Response(JSON.stringify({ token, expires_at: expiresAt }), {
      status: 201,
    });
  }

  const config = {
    github: { app_id: 1, installation_id: 42 },
  } as unknown as AutopilotConfig;

  test("fetches and returns installation token", async () => {
    fetchSpy.mockResolvedValue(makeTokenResponse("ghs_abc123"));
    const token = await getGitHubAppToken(config);
    expect(token).toBe("ghs_abc123");
    expect(fetchSpy).toHaveBeenCalledTimes(1);
  });

  test("returns cached token without re-fetching on second call", async () => {
    fetchSpy.mockResolvedValue(makeTokenResponse("ghs_cached"));
    await getGitHubAppToken(config);
    const token2 = await getGitHubAppToken(config);
    expect(token2).toBe("ghs_cached");
    expect(fetchSpy).toHaveBeenCalledTimes(1);
  });

  test("refreshes token when within 5 minutes of expiry", async () => {
    fetchSpy
      .mockResolvedValueOnce(
        makeTokenResponse("ghs_expiring_soon", 4 * 60_000),
      )
      .mockResolvedValueOnce(makeTokenResponse("ghs_fresh"));
    await getGitHubAppToken(config);
    const token = await getGitHubAppToken(config);
    expect(token).toBe("ghs_fresh");
    expect(fetchSpy).toHaveBeenCalledTimes(2);
  });

  test("concurrent callers during refresh share one in-flight promise", async () => {
    let resolveFirst!: (v: Response) => void;
    const inflightPromise = new Promise<Response>((res) => {
      resolveFirst = res;
    });
    fetchSpy.mockReturnValue(inflightPromise);

    const p1 = getGitHubAppToken(config);
    const p2 = getGitHubAppToken(config);

    const expiresAt = new Date(Date.now() + 3_600_000).toISOString();
    resolveFirst(
      new Response(
        JSON.stringify({ token: "ghs_shared", expires_at: expiresAt }),
        { status: 201 },
      ),
    );

    const [t1, t2] = await Promise.all([p1, p2]);
    expect(t1).toBe("ghs_shared");
    expect(t2).toBe("ghs_shared");
    expect(fetchSpy).toHaveBeenCalledTimes(1);
  });
});
