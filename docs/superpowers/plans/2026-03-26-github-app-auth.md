# GitHub App Authentication Implementation Plan

> **For agentic workers:** REQUIRED: Use superpowers:subagent-driven-development (if subagents available) or superpowers:executing-plans to implement this plan. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add GitHub App authentication as an alternative to PATs, with automatic installation token generation/refresh and no breaking changes for existing PAT users.

**Architecture:** A module-level token cache in `github-app-auth.ts` is the shared state. `initGitHubAuth(config)` warms the cache at startup. `getCachedAppToken()` gives synchronous access to the current token. Three modules read from it: `github.ts` (Octokit client), `agent-config.ts` (MCP server env + agent env), and `sandbox-clone.ts` (git remote URL rewrite). No callers of `runClaude()`, `buildMcpServers()`, or `createClone()` need to change. The GitHub MCP server switches from the Copilot-hosted HTTP endpoint to `@github/github-mcp-server` run locally via stdio.

**Tech Stack:** Bun, TypeScript, Node.js built-in `crypto` (no new deps), Octokit, `@github/github-mcp-server` (npx, not installed)

**Spec:** `docs/superpowers/specs/2026-03-26-github-app-auth-design.md`

---

## Chunk 1: Config fields + github-app-auth module

### Task 1: Add `app_id` and `installation_id` to config

**Files:**
- Modify: `src/lib/config.ts`
- Modify: `src/lib/config.test.ts`

- [ ] **Step 1: Update the import in `src/lib/config.test.ts`**

Find the existing import line (currently `import { collectUnknownKeys, DEFAULTS, deepMerge, loadConfig } from "./config"`) and add `AutopilotConfig`:

```typescript
import { type AutopilotConfig, collectUnknownKeys, DEFAULTS, deepMerge, loadConfig } from "./config";
```

- [ ] **Step 2: Write failing tests**

Add to `src/lib/config.test.ts` (after the existing describe blocks):

```typescript
describe("github app auth config", () => {
  test("app_id and installation_id default to 0", () => {
    const config = deepMerge(
      DEFAULTS as unknown as Record<string, unknown>,
      {},
    ) as unknown as AutopilotConfig;
    expect(config.github.app_id).toBe(0);
    expect(config.github.installation_id).toBe(0);
  });

  test("app_id and installation_id are loaded from yaml", () => {
    const config = deepMerge(
      DEFAULTS as unknown as Record<string, unknown>,
      { github: { app_id: 12345, installation_id: 67890 } },
    ) as unknown as AutopilotConfig;
    expect(config.github.app_id).toBe(12345);
    expect(config.github.installation_id).toBe(67890);
  });
});
```

- [ ] **Step 3: Run tests to verify they fail**

```bash
bun test src/lib/config.test.ts 2>&1 | tail -20
```

Expected: FAIL — `app_id` does not exist on `GithubConfig`.

- [ ] **Step 4: Add fields to `GithubConfig` and `DEFAULTS`**

In `src/lib/config.ts`, update the `GithubConfig` interface:

```typescript
export interface GithubConfig {
  repo: string;
  automerge: boolean;
  app_id: number;          // 0 = not configured
  installation_id: number; // 0 = not configured
}
```

Update the `github` entry in `DEFAULTS`:

```typescript
github: {
  repo: "",
  automerge: false,
  app_id: 0,
  installation_id: 0,
},
```

- [ ] **Step 5: Run tests to verify they pass**

```bash
bun test src/lib/config.test.ts 2>&1 | tail -20
```

Expected: PASS.

- [ ] **Step 6: Run full test suite to check for regressions**

```bash
bun test 2>&1 | tail -20
```

Expected: all existing tests still pass.

- [ ] **Step 7: Commit**

```bash
git add src/lib/config.ts src/lib/config.test.ts
git commit -m "feat: add github.app_id and github.installation_id config fields"
```

---

### Task 2: Create `github-app-auth.ts` — private key loading and JWT generation

**Files:**
- Create: `src/lib/github-app-auth.ts`
- Create: `src/lib/github-app-auth.test.ts`

- [ ] **Step 1: Create the test file with tests for `loadPrivateKey` and `generateJWT`**

Create `src/lib/github-app-auth.test.ts`:

```typescript
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
```

- [ ] **Step 2: Run tests to verify they fail**

```bash
bun test src/lib/github-app-auth.test.ts 2>&1 | tail -20
```

Expected: FAIL — module does not exist.

- [ ] **Step 3: Create `github-app-auth.ts`**

Create `src/lib/github-app-auth.ts`:

```typescript
import { createSign } from "node:crypto";
import { readFileSync } from "node:fs";
import type { AutopilotConfig } from "./config";
import { withRetry } from "./retry";

// ---------------------------------------------------------------------------
// Module-level cache
// ---------------------------------------------------------------------------

interface CachedToken {
  token: string;
  expiresAt: Date;
}

let _cached: CachedToken | null = null;
let _inFlight: Promise<CachedToken> | null = null;

export function resetAppAuthCache(): void {
  _cached = null;
  _inFlight = null;
}

// ---------------------------------------------------------------------------
// Private key loading
// ---------------------------------------------------------------------------

/** Reads the GitHub App private key.
 * Prefers GITHUB_APP_PRIVATE_KEY (inline PEM) over GITHUB_APP_PRIVATE_KEY_PATH (file path). */
export function loadPrivateKey(): string {
  const inline = process.env.GITHUB_APP_PRIVATE_KEY;
  if (inline) return inline;

  const keyPath = process.env.GITHUB_APP_PRIVATE_KEY_PATH;
  if (keyPath) return readFileSync(keyPath, "utf-8");

  throw new Error(
    "GitHub App auth is configured (app_id/installation_id) but no private key found. " +
      "Set GITHUB_APP_PRIVATE_KEY or GITHUB_APP_PRIVATE_KEY_PATH.",
  );
}

// ---------------------------------------------------------------------------
// JWT generation
// ---------------------------------------------------------------------------

function base64url(buf: Buffer): string {
  return buf
    .toString("base64")
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=/g, "");
}

/** Generates a GitHub App JWT valid for ~9 minutes (within GitHub's 10-min max). */
export function generateJWT(appId: number, privateKey: string): string {
  const t = Math.floor(Date.now() / 1000);
  const header = base64url(
    Buffer.from(JSON.stringify({ alg: "RS256", typ: "JWT" })),
  );
  const payload = base64url(
    Buffer.from(
      JSON.stringify({ iat: t - 60, exp: t + 540, iss: String(appId) }),
    ),
  );
  const data = `${header}.${payload}`;
  const signer = createSign("RSA-SHA256");
  signer.update(data);
  const sig = base64url(signer.sign(privateKey));
  return `${data}.${sig}`;
}

// ---------------------------------------------------------------------------
// App auth detection
// ---------------------------------------------------------------------------

export function isAppAuthConfigured(config: AutopilotConfig): boolean {
  return (
    config.github.app_id !== 0 &&
    config.github.installation_id !== 0 &&
    !!(
      process.env.GITHUB_APP_PRIVATE_KEY ||
      process.env.GITHUB_APP_PRIVATE_KEY_PATH
    )
  );
}

// ---------------------------------------------------------------------------
// Synchronous cache accessor (for use in sync callers)
// ---------------------------------------------------------------------------

/** Returns the cached token if still valid (>5 min remaining), else null.
 * Callers that need a guaranteed-fresh token should use getGitHubAppToken(). */
export function getCachedAppToken(): string | null {
  const fiveMinutes = 5 * 60 * 1000;
  if (_cached && _cached.expiresAt.getTime() - Date.now() > fiveMinutes) {
    return _cached.token;
  }
  return null;
}

// ---------------------------------------------------------------------------
// Installation token fetching
// ---------------------------------------------------------------------------

async function fetchInstallationToken(
  appId: number,
  installationId: number,
  privateKey: string,
): Promise<CachedToken> {
  const jwt = generateJWT(appId, privateKey);
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
      ).then(async (res) => {
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

// ---------------------------------------------------------------------------
// Public token accessor (with lazy refresh + in-flight deduplication)
// ---------------------------------------------------------------------------

/** Returns a valid GitHub installation token, refreshing if within 5 minutes of expiry.
 * Concurrent callers during a refresh share one in-flight promise. */
export async function getGitHubAppToken(
  config: AutopilotConfig,
): Promise<string> {
  const fiveMinutes = 5 * 60 * 1000;

  if (_cached && _cached.expiresAt.getTime() - Date.now() > fiveMinutes) {
    return _cached.token;
  }

  if (!_inFlight) {
    const privateKey = loadPrivateKey();
    _inFlight = fetchInstallationToken(
      config.github.app_id,
      config.github.installation_id,
      privateKey,
    ).then((result) => {
      _cached = result;
      _inFlight = null;
      return result;
    });
  }

  const result = await _inFlight;
  return result.token;
}
```

- [ ] **Step 4: Run tests to verify they pass**

```bash
bun test src/lib/github-app-auth.test.ts 2>&1 | tail -20
```

Expected: all pass.

- [ ] **Step 5: Commit**

```bash
git add src/lib/github-app-auth.ts src/lib/github-app-auth.test.ts
git commit -m "feat: add github-app-auth module (JWT, token fetching, cache)"
```

---

### Task 3: Add `getGitHubAppToken` caching tests

**Files:**
- Modify: `src/lib/github-app-auth.test.ts`

- [ ] **Step 1: Write failing tests for token caching and in-flight deduplication**

Add to `src/lib/github-app-auth.test.ts`:

```typescript
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
  } as AutopilotConfig;

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
```

Also add the `AutopilotConfig` import at the top of the test file:

```typescript
import type { AutopilotConfig } from "./config";
```

- [ ] **Step 2: Run tests to verify they fail**

```bash
bun test src/lib/github-app-auth.test.ts --test-name-pattern "getGitHubAppToken" 2>&1 | tail -20
```

Expected: FAIL (compile error or test failures since tests reference new behaviors).

- [ ] **Step 3: Run tests to verify they pass (implementation already exists from Task 2)**

```bash
bun test src/lib/github-app-auth.test.ts 2>&1 | tail -20
```

Expected: all pass — the implementation was written in Task 2.

- [ ] **Step 4: Commit**

```bash
git add src/lib/github-app-auth.test.ts
git commit -m "test: add token caching and dedup tests for github-app-auth"
```

---

## Chunk 2: Wire App auth into `github.ts`, `agent-config.ts`, and `main.ts`

### Task 4: Add `initGitHubAuth` to `github.ts`

**Files:**
- Modify: `src/lib/github.ts`
- Modify: `src/lib/github.test.ts`

The key insight: `getGitHubClient()` is synchronous. It reads the App token via `getCachedAppToken()` (sync). The cache is pre-warmed by `initGitHubAuth()` (async) at startup. After that, any call to `getGitHubAppToken()` (from the main loop or agent spawn) keeps it warm.

- [ ] **Step 1: Write failing tests**

Add to `src/lib/github.test.ts`. Place this BEFORE the existing `import` statements (so mock.module runs before the module loads):

```typescript
// Mock github-app-auth to control App auth behavior in tests
let mockCachedToken: string | null = null;
let mockAppConfigured = false;

mock.module("./github-app-auth", () => ({
  isAppAuthConfigured: () => mockAppConfigured,
  getCachedAppToken: () => mockCachedToken,
  getGitHubAppToken: async () => mockCachedToken ?? "ghs_mock",
  resetAppAuthCache: () => {},
}));
```

Then add a new describe block after the existing tests:

```typescript
describe("initGitHubAuth + App auth path", () => {
  beforeEach(() => {
    resetClient();
    mockAppConfigured = false;
    mockCachedToken = null;
  });

  test("getGitHubClient uses GITHUB_TOKEN env var when App auth is not configured", () => {
    // process.env.GITHUB_TOKEN is set at top of file as "test-token-github"
    const client = getGitHubClient();
    expect(client).toBeDefined();
  });

  test("getGitHubClient throws descriptive error when neither App auth nor GITHUB_TOKEN is configured", () => {
    const saved = process.env.GITHUB_TOKEN;
    delete process.env.GITHUB_TOKEN;
    resetClient();
    expect(() => getGitHubClient()).toThrow("No GitHub credentials found");
    process.env.GITHUB_TOKEN = saved;
  });

  test("getGitHubClient uses cached App token when App auth is configured and cache is warm", () => {
    mockAppConfigured = true;
    mockCachedToken = "ghs_warm_token";
    resetClient();
    // Should not throw — uses cached token
    const client = getGitHubClient();
    expect(client).toBeDefined();
  });

  test("getGitHubClient recreates Octokit when cached App token changes", () => {
    mockAppConfigured = true;
    mockCachedToken = "ghs_token_v1";
    resetClient();
    const client1 = getGitHubClient();
    mockCachedToken = "ghs_token_v2";
    const client2 = getGitHubClient();
    expect(client1).not.toBe(client2);
  });
});
```

Also add `initGitHubAuth` to the import from `./github`:

```typescript
import {
  detectRepo,
  enableAutoMerge,
  getPRReviewInfo,
  getPRStatus,
  initGitHubAuth,
  resetClient,
} from "./github";
```

- [ ] **Step 2: Run tests to verify they fail**

```bash
bun test src/lib/github.test.ts --test-name-pattern "initGitHubAuth" 2>&1 | tail -20
```

Expected: FAIL — `initGitHubAuth` not exported from `github.ts`.

- [ ] **Step 3: Update `github.ts`**

Add imports at the top of `src/lib/github.ts`:

```typescript
import type { AutopilotConfig } from "./config";
import { getCachedAppToken, getGitHubAppToken, isAppAuthConfigured } from "./github-app-auth";
```

Replace the existing module-level state and `getGitHubClient` / `resetClient` with:

```typescript
let _client: Octokit | null = null;
let _clientToken: string | null = null;
let _config: AutopilotConfig | null = null;

/**
 * Call once at startup with the loaded config to enable GitHub App auth.
 * Warms the token cache so getGitHubClient() can work synchronously.
 */
export async function initGitHubAuth(config: AutopilotConfig): Promise<void> {
  _config = config;
  if (isAppAuthConfigured(config)) {
    await getGitHubAppToken(config);
  }
}

/**
 * Get or create the Octokit client.
 * Uses GitHub App installation token if configured via initGitHubAuth(),
 * otherwise falls back to GITHUB_TOKEN environment variable.
 */
export function getGitHubClient(): Octokit {
  if (_config && isAppAuthConfigured(_config)) {
    const appToken = getCachedAppToken();
    if (appToken) {
      if (_client && _clientToken === appToken) return _client;
      _client = new Octokit({ auth: appToken });
      _clientToken = appToken;
      return _client;
    }
  }

  const token = process.env.GITHUB_TOKEN;
  if (!token) {
    throw new Error(
      "No GitHub credentials found. Either set GITHUB_TOKEN (personal access token) or " +
        "configure github.app_id + github.installation_id in .autopilot.yml with " +
        "GITHUB_APP_PRIVATE_KEY / GITHUB_APP_PRIVATE_KEY_PATH.",
    );
  }

  if (_client && !_clientToken) return _client;
  _client = new Octokit({ auth: token });
  _clientToken = null; // null = PAT client (distinguish from App token string)
  return _client;
}

/**
 * Reset the cached client and config. Used in tests to prevent singleton leakage.
 */
export function resetClient(): void {
  _client = null;
  _clientToken = null;
  _config = null;
}
```

- [ ] **Step 4: Run tests**

```bash
bun test src/lib/github.test.ts 2>&1 | tail -20
```

Expected: all pass.

- [ ] **Step 5: Run full test suite**

```bash
bun test 2>&1 | tail -20
```

Expected: all pass.

- [ ] **Step 6: Commit**

```bash
git add src/lib/github.ts src/lib/github.test.ts
git commit -m "feat: add initGitHubAuth to github.ts, wire App token via sync cache"
```

---

### Task 5: Update `agent-config.ts` — switch GitHub MCP server and use cached token

**Files:**
- Modify: `src/lib/agent-config.ts`
- Modify: `src/lib/agent-config.test.ts`

The strategy: `buildMcpServers` and `buildAgentEnv` import `getCachedAppToken` from `github-app-auth` and use it as a fallback when no explicit token is passed. No callers need to change — the cache is warm after `initGitHubAuth` has run.

- [ ] **Step 1: Write failing tests**

Update `src/lib/agent-config.test.ts`. First add imports:

```typescript
import { afterEach, beforeEach, describe, expect, test } from "bun:test";
import { buildAgentEnv, buildMcpServers } from "./agent-config";
```

Add new describe blocks:

```typescript
describe("buildMcpServers — github MCP server", () => {
  let savedLinearKey: string | undefined;
  let savedGithubToken: string | undefined;

  beforeEach(() => {
    savedLinearKey = process.env.LINEAR_API_KEY;
    savedGithubToken = process.env.GITHUB_TOKEN;
    process.env.LINEAR_API_KEY = "lin_test";
  });

  afterEach(() => {
    if (savedLinearKey === undefined) delete process.env.LINEAR_API_KEY;
    else process.env.LINEAR_API_KEY = savedLinearKey;
    if (savedGithubToken === undefined) delete process.env.GITHUB_TOKEN;
    else process.env.GITHUB_TOKEN = savedGithubToken;
  });

  test("github MCP server is stdio type pointing to github-mcp-server", () => {
    const servers = buildMcpServers();
    const gh = servers.github as { type: string; command: string; args: string[] };
    expect(gh.type).toBe("stdio");
    expect(gh.command).toBe("npx");
    expect(gh.args).toContain("@github/github-mcp-server@latest");
  });

  test("github MCP server env uses GITHUB_TOKEN when set", () => {
    process.env.GITHUB_TOKEN = "ghp_from_env";
    const servers = buildMcpServers();
    const gh = servers.github as { env: { GITHUB_TOKEN: string } };
    expect(gh.env.GITHUB_TOKEN).toBe("ghp_from_env");
  });
});

describe("buildAgentEnv — github token", () => {
  test("includes GITHUB_TOKEN from env when set", () => {
    process.env.GITHUB_TOKEN = "ghp_in_env";
    const env = buildAgentEnv();
    expect(env.GITHUB_TOKEN).toBe("ghp_in_env");
    delete process.env.GITHUB_TOKEN;
  });

  test("GITHUB_TOKEN is absent when env var is not set", () => {
    delete process.env.GITHUB_TOKEN;
    const env = buildAgentEnv();
    expect(env.GITHUB_TOKEN).toBeUndefined();
  });
});
```

- [ ] **Step 2: Run tests to verify they fail**

```bash
bun test src/lib/agent-config.test.ts 2>&1 | tail -20
```

Expected: FAIL — github MCP is still HTTP type, not stdio.

- [ ] **Step 3: Update `agent-config.ts`**

Add import at the top of `src/lib/agent-config.ts`:

```typescript
import { getCachedAppToken } from "./github-app-auth";
```

Update `SANDBOX_BASE_DOMAINS` — remove `api.githubcopilot.com`:

```typescript
export const SANDBOX_BASE_DOMAINS = [
  "github.com",
  "api.github.com",
  "mcp.linear.app",
];
```

In `buildMcpServers`, replace the `github` entry:

```typescript
const githubToken = getCachedAppToken() ?? process.env.GITHUB_TOKEN;

// ... (keep existing linear and autopilot entries unchanged) ...

github: {
  type: "stdio",
  command: "npx",
  args: ["-y", "@github/github-mcp-server@latest", "stdio"],
  env: { GITHUB_TOKEN: githubToken },
},
```

The existing `buildAgentEnv` already forwards `GITHUB_TOKEN` from `process.env` via the `AGENT_ENV_ALLOWLIST` — no changes needed there. The cache populates `process.env.GITHUB_TOKEN` indirectly through the `AGENT_ENV_ALLOWLIST` for PAT users, and the App token is injected via `getCachedAppToken()` in `buildMcpServers`. However, to ensure the App token also reaches the agent subprocess env (for git operations), update `buildAgentEnv` to check the App token cache:

```typescript
export function buildAgentEnv(): Record<string, string> {
  const env: Record<string, string> = {};
  for (const key of AGENT_ENV_ALLOWLIST) {
    if (process.env[key]) {
      env[key] = process.env[key] as string;
    }
  }
  // Override GITHUB_TOKEN with App token if available (takes precedence over PAT in env)
  const appToken = getCachedAppToken();
  if (appToken) {
    env.GITHUB_TOKEN = appToken;
  }
  env.CLAUDE_CODE_EXPERIMENTAL_AGENT_TEAMS = "1";
  env.GIT_CONFIG_NOSYSTEM = "1";
  return env;
}
```

- [ ] **Step 4: Run tests**

```bash
bun test src/lib/agent-config.test.ts 2>&1 | tail -20
```

Expected: all pass.

- [ ] **Step 5: Run full test suite**

```bash
bun test 2>&1 | tail -20
```

Expected: all pass.

- [ ] **Step 6: Commit**

```bash
git add src/lib/agent-config.ts src/lib/agent-config.test.ts
git commit -m "feat: switch GitHub MCP to stdio github-mcp-server, use App token cache"
```

---

### Task 6: Rewrite git remote URL in clones when App token is cached

**Files:**
- Modify: `src/lib/sandbox-clone.ts`
- Modify: `src/lib/sandbox-clone.test.ts`

`createClone` reads `getCachedAppToken()` internally — no signature change needed, no callers to update.

- [ ] **Step 1: Write failing tests**

Add a top-level `mock.module` call and a closure variable at the top of `src/lib/sandbox-clone.test.ts`, BEFORE the `import { ... } from "./sandbox-clone"` line. Bun hoists `mock.module` before module evaluation — this is the same pattern as `github.test.ts` line 52.

```typescript
// Control getCachedAppToken return value per-test via this variable
let mockAppToken: string | null = null;

mock.module("./github-app-auth", () => ({
  getCachedAppToken: () => mockAppToken,
}));
```

Also update the `bun:test` import to include `mock`:

```typescript
import { afterEach, beforeEach, describe, expect, mock, spyOn, test } from "bun:test";
```

Then reset `mockAppToken` in the existing outer `beforeEach` (add one line):

```typescript
beforeEach(() => {
  mockAppToken = null; // reset per-test — no App token by default
  existsSpy = spyOn(fs, "existsSync").mockReturnValue(false);
  // ... rest of existing beforeEach unchanged ...
});
```

Then add the new describe block after the existing ones:

```typescript
describe("createClone — App token remote URL rewrite", () => {
  test("rewrites SSH remote URL to HTTPS with App token when cache is warm", async () => {
    mockAppToken = "ghs_app_token";
    const calls: string[][] = [];
    spawnSpy = spyOn(Bun, "spawnSync").mockImplementation((cmd: string[]) => {
      calls.push([...cmd]);
      if (cmd[1] === "remote" && cmd[2] === "get-url") {
        return spawnOk("git@github.com:owner/repo.git");
      }
      if (cmd[1] === "symbolic-ref") return spawnOk("refs/remotes/origin/main");
      return spawnOk();
    });

    await createClone(PROJECT, "test-app-clone");

    const tokenSetUrl = calls.find(
      (c) =>
        c[1] === "remote" &&
        c[2] === "set-url" &&
        c[3] === "origin" &&
        c[4]?.includes("x-access-token"),
    );
    expect(tokenSetUrl).toBeDefined();
    expect(tokenSetUrl![4]).toBe(
      "https://x-access-token:ghs_app_token@github.com/owner/repo.git",
    );
  });

  test("rewrites HTTPS remote URL to HTTPS with App token", async () => {
    mockAppToken = "ghs_https_token";
    const calls: string[][] = [];
    spawnSpy = spyOn(Bun, "spawnSync").mockImplementation((cmd: string[]) => {
      calls.push([...cmd]);
      if (cmd[1] === "remote" && cmd[2] === "get-url") {
        return spawnOk("https://github.com/owner/repo.git");
      }
      if (cmd[1] === "symbolic-ref") return spawnOk("refs/remotes/origin/main");
      return spawnOk();
    });

    await createClone(PROJECT, "test-app-clone2");

    const tokenSetUrl = calls.find(
      (c) => c[1] === "remote" && c[2] === "set-url" && c[4]?.includes("x-access-token"),
    );
    expect(tokenSetUrl).toBeDefined();
    expect(tokenSetUrl![4]).toBe(
      "https://x-access-token:ghs_https_token@github.com/owner/repo.git",
    );
  });

  test("does not rewrite remote URL when App token cache is empty", async () => {
    mockAppToken = null; // no App auth
    const calls: string[][] = [];
    spawnSpy = spyOn(Bun, "spawnSync").mockImplementation((cmd: string[]) => {
      calls.push([...cmd]);
      if (cmd[1] === "remote" && cmd[2] === "get-url") {
        return spawnOk("git@github.com:owner/repo.git");
      }
      if (cmd[1] === "symbolic-ref") return spawnOk("refs/remotes/origin/main");
      return spawnOk();
    });

    await createClone(PROJECT, "test-no-token-clone");

    const tokenSetUrl = calls.find(
      (c) => c[1] === "remote" && c[2] === "set-url" && c[4]?.includes("x-access-token"),
    );
    expect(tokenSetUrl).toBeUndefined();
  });
});

- [ ] **Step 2: Run tests to verify they fail**

```bash
bun test src/lib/sandbox-clone.test.ts --test-name-pattern "App token" 2>&1 | tail -20
```

Expected: FAIL — `createClone` doesn't read from `getCachedAppToken`.

- [ ] **Step 3: Update `createClone` in `sandbox-clone.ts`**

Add import at the top of `src/lib/sandbox-clone.ts`:

```typescript
import { getCachedAppToken } from "./github-app-auth";
```

In `createClone`, after the existing `gitSync(dest, ["remote", "set-url", "origin", githubUrl])` call (around line 170), add:

```typescript
// When using GitHub App auth, rewrite the remote URL to embed the installation token
// so git push works without SSH keys. Handles both SSH and HTTPS original remotes.
// The token is short-lived (~1h) but matches the agent run lifetime.
const appToken = getCachedAppToken();
if (appToken) {
  const httpsMatch = githubUrl.match(/github\.com\/([^/]+)\/([^/.]+)/);
  const sshMatch = githubUrl.match(/github\.com:([^/]+)\/([^/.]+)/);
  const match = httpsMatch ?? sshMatch;
  if (match) {
    const tokenUrl = `https://x-access-token:${appToken}@github.com/${match[1]}/${match[2]}.git`;
    const tokenUrlErr = gitSync(dest, ["remote", "set-url", "origin", tokenUrl]);
    if (tokenUrlErr) {
      throw new Error(
        `Failed to set token remote URL in clone '${name}': ${tokenUrlErr}`,
      );
    }
  }
}
```

- [ ] **Step 4: Run tests**

```bash
bun test src/lib/sandbox-clone.test.ts 2>&1 | tail -20
```

Expected: all pass including new tests.

- [ ] **Step 5: Run full test suite**

```bash
bun test 2>&1 | tail -20
```

Expected: all pass.

- [ ] **Step 6: Commit**

```bash
git add src/lib/sandbox-clone.ts src/lib/sandbox-clone.test.ts
git commit -m "feat: rewrite git remote URL with App token in clones"
```

---

## Chunk 3: Main entry point wiring + final checks

### Task 7: Wire `initGitHubAuth` into `main.ts` and add periodic cache warmup

**Files:**
- Modify: `src/main.ts`

The main loop needs to:
1. Call `initGitHubAuth(config)` early — this warms the token cache before `detectRepo` calls `getGitHubClient()`
2. Add periodic `getGitHubAppToken(config)` calls in the main loop to keep the cache warm (so the monitor/planner's sync `getGitHubClient()` calls always find a valid cached token)

- [ ] **Step 1: Add `initGitHubAuth` import and call to `main.ts`**

Find this line in `src/main.ts`:

```typescript
import { detectRepo } from "./lib/github";
```

Change it to:

```typescript
import { detectRepo, initGitHubAuth } from "./lib/github";
```

Find where `loadConfig` is called (it's early in main). After the `loadConfig(...)` call and before `detectRepo(...)`, add:

```typescript
await initGitHubAuth(config);
```

Also add a startup log line inside `initGitHubAuth` in `github.ts` so users can confirm App auth is active.

First, update the logger import in `src/lib/github.ts`. Find the existing line:

```typescript
import { warn } from "./logger";
```

Change it to:

```typescript
import { info, warn } from "./logger";
```

Then update `initGitHubAuth` in `github.ts`:

```typescript
export async function initGitHubAuth(config: AutopilotConfig): Promise<void> {
  _config = config;
  if (isAppAuthConfigured(config)) {
    await getGitHubAppToken(config);
    info(`GitHub App auth active (app_id: ${config.github.app_id})`);
  }
}
```

- [ ] **Step 2: Add periodic token warmup in the main loop**

Find the main event loop in `main.ts` (the `while (true)` or equivalent). At the top of each loop iteration, add:

```typescript
// Keep the GitHub App token cache warm for sync callers (monitor, planner)
if (isAppAuthConfigured(config)) {
  await getGitHubAppToken(config);
}
```

Add the necessary imports to `main.ts`:

```typescript
import { isAppAuthConfigured, getGitHubAppToken } from "./lib/github-app-auth";
```

- [ ] **Step 3: Run the full test suite**

```bash
bun test 2>&1 | tail -30
```

Expected: all pass.

- [ ] **Step 4: Typecheck**

```bash
bun run typecheck 2>&1 | tail -20
```

Expected: no errors.

- [ ] **Step 5: Lint**

```bash
bun run check 2>&1 | tail -20
```

Expected: no errors. If there are import-order issues, run `bunx biome check --write ./src`.

- [ ] **Step 6: Commit**

```bash
git add src/main.ts src/lib/github.ts
git commit -m "feat: wire initGitHubAuth into main.ts with periodic token warmup"
```

---

## Manual verification checklist

After implementation, verify end-to-end with a real GitHub App:

1. Create a GitHub App at `https://github.com/settings/apps/new`
   - Permissions needed: Contents (read/write), Pull requests (read/write), Checks (read), Metadata (read)
2. Download the private key (`.pem` file)
3. Install the App on your target repo — note the Installation ID from the URL: `github.com/settings/installations/{id}`
4. Add to `.autopilot.yml`:
   ```yaml
   github:
     app_id: <your-app-id>
     installation_id: <your-installation-id>
   ```
5. Set env:
   ```bash
   export GITHUB_APP_PRIVATE_KEY_PATH=/path/to/private-key.pem
   # Do NOT set GITHUB_TOKEN — verify PAT fallback is not active
   ```
6. Run `bun run start <project-path>`
7. Confirm startup log shows: `GitHub App auth active (app_id: <id>)`
8. Verify a PR is created and merged successfully on a test issue
