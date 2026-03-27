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
      JSON.stringify({ iat: t - 60, exp: t - 60 + 540, iss: String(appId) }),
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
    (
      !!process.env.GITHUB_APP_PRIVATE_KEY ||
      !!process.env.GITHUB_APP_PRIVATE_KEY_PATH
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
