import {
  afterEach,
  beforeEach,
  describe,
  expect,
  spyOn,
  test,
} from "bun:test";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { generateKeyPairSync } from "node:crypto";
import type { AutopilotConfig } from "./config";

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
    if (savedKeyPath === undefined) delete process.env.GITHUB_APP_PRIVATE_KEY_PATH;
    else process.env.GITHUB_APP_PRIVATE_KEY_PATH = savedKeyPath;
  });

  test("returns inline PEM from GITHUB_APP_PRIVATE_KEY", () => {
    process.env.GITHUB_APP_PRIVATE_KEY = "inline-pem-content";
    const { loadPrivateKey } = require("./github-app-auth");
    expect(loadPrivateKey()).toBe("inline-pem-content");
  });

  test("reads PEM from file when GITHUB_APP_PRIVATE_KEY_PATH is set", () => {
    const dir = mkdtempSync(join(tmpdir(), "gh-app-test-"));
    const keyPath = join(dir, "key.pem");
    writeFileSync(keyPath, "file-pem-content");
    process.env.GITHUB_APP_PRIVATE_KEY_PATH = keyPath;
    const { loadPrivateKey } = require("./github-app-auth");
    expect(loadPrivateKey()).toBe("file-pem-content");
    rmSync(dir, { recursive: true });
  });

  test("prefers inline env over file path when both are set", () => {
    process.env.GITHUB_APP_PRIVATE_KEY = "inline-wins";
    process.env.GITHUB_APP_PRIVATE_KEY_PATH = "/ignored/path";
    const { loadPrivateKey } = require("./github-app-auth");
    expect(loadPrivateKey()).toBe("inline-wins");
  });

  test("throws when neither env var is set", () => {
    const { loadPrivateKey } = require("./github-app-auth");
    expect(() => loadPrivateKey()).toThrow("GITHUB_APP_PRIVATE_KEY");
  });
});

// ---------------------------------------------------------------------------
// generateJWT
// ---------------------------------------------------------------------------

describe("generateJWT", () => {
  // Generate a real RSA key once for all JWT tests
  const { privateKey } = generateKeyPairSync("rsa", { modulusLength: 2048 });
  const pem = privateKey.export({ type: "pkcs8", format: "pem" }) as string;

  test("JWT header decodes to alg:RS256 and typ:JWT", () => {
    const { generateJWT } = require("./github-app-auth");
    const jwt = generateJWT(12345, pem);
    const [headerB64] = jwt.split(".");
    const header = JSON.parse(Buffer.from(headerB64, "base64url").toString());
    expect(header.alg).toBe("RS256");
    expect(header.typ).toBe("JWT");
  });

  test("JWT has three dot-separated parts", () => {
    const { generateJWT } = require("./github-app-auth");
    const jwt = generateJWT(1, pem);
    expect(jwt.split(".")).toHaveLength(3);
  });

  test("JWT payload has iss as string, iat and exp as Unix seconds", () => {
    const { generateJWT } = require("./github-app-auth");
    const before = Math.floor(Date.now() / 1000);
    const jwt = generateJWT(99, pem);
    const after = Math.floor(Date.now() / 1000);

    const [, payloadB64] = jwt.split(".");
    const payload = JSON.parse(Buffer.from(payloadB64, "base64url").toString());

    expect(typeof payload.iss).toBe("string");
    expect(payload.iss).toBe("99");
    // iat is backdated by ~60s
    expect(payload.iat).toBeGreaterThanOrEqual(before - 61);
    expect(payload.iat).toBeLessThanOrEqual(after - 59);
    // exp = iat + 540 (9 minutes)
    expect(payload.exp).toBe(payload.iat + 540);
    // Sanity: iat and exp are integer seconds, not milliseconds (would be ~1e12)
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
    const { resetAppAuthCache } = require("./github-app-auth");
    resetAppAuthCache();
  });

  afterEach(() => {
    delete process.env.GITHUB_APP_PRIVATE_KEY;
    fetchSpy.mockRestore();
  });

  function makeTokenResponse(token: string, expiresInMs = 3_600_000) {
    const expiresAt = new Date(Date.now() + expiresInMs).toISOString();
    return new Response(
      JSON.stringify({ token, expires_at: expiresAt }),
      { status: 201 },
    );
  }

  const config = {
    github: { app_id: 1, installation_id: 42 },
  } as unknown as AutopilotConfig;

  test("fetches and returns installation token", async () => {
    fetchSpy.mockResolvedValue(makeTokenResponse("ghs_abc123"));
    const { getGitHubAppToken } = require("./github-app-auth");
    const token = await getGitHubAppToken(config);
    expect(token).toBe("ghs_abc123");
    expect(fetchSpy).toHaveBeenCalledTimes(1);
  });

  test("returns cached token without re-fetching on second call", async () => {
    fetchSpy.mockResolvedValue(makeTokenResponse("ghs_cached"));
    const { getGitHubAppToken } = require("./github-app-auth");
    await getGitHubAppToken(config);
    const token2 = await getGitHubAppToken(config);
    expect(token2).toBe("ghs_cached");
    expect(fetchSpy).toHaveBeenCalledTimes(1);
  });

  test("refreshes token when within 5 minutes of expiry", async () => {
    fetchSpy
      .mockResolvedValueOnce(makeTokenResponse("ghs_expiring_soon", 4 * 60_000))
      .mockResolvedValueOnce(makeTokenResponse("ghs_fresh"));
    const { getGitHubAppToken } = require("./github-app-auth");
    await getGitHubAppToken(config); // populates cache with near-expiry token
    const token = await getGitHubAppToken(config); // should refresh
    expect(token).toBe("ghs_fresh");
    expect(fetchSpy).toHaveBeenCalledTimes(2);
  });

  test("concurrent callers during refresh share one in-flight promise", async () => {
    let resolveFirst!: (v: Response) => void;
    const inflightPromise = new Promise<Response>((res) => {
      resolveFirst = res;
    });
    fetchSpy.mockReturnValue(inflightPromise);

    const { getGitHubAppToken } = require("./github-app-auth");
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
