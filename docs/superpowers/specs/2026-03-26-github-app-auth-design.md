# GitHub App Authentication Design

**Date:** 2026-03-26
**Status:** Approved

## Overview

Add support for GitHub App authentication as an alternative to personal access tokens (PATs). Users configure an App ID and Installation ID in `.autopilot.yml`; the private key is provided via environment variable. Autopilot generates short-lived installation access tokens automatically, refreshing them before expiry.

The GitHub MCP server is switched from the Copilot-hosted endpoint (`api.githubcopilot.com/mcp/`) to `github/github-mcp-server` run locally via stdio, which works with standard GitHub tokens including installation tokens.

## Motivation

PATs are tied to individual user accounts, have broad scopes, and don't expire. GitHub Apps are the recommended machine identity for CI/CD systems: they have granular permissions, tokens expire automatically, and activity is attributed to the app rather than a user.

## Architecture

### Auth Initialization

At startup (in `main.ts` and any other entry point that uses GitHub), call `initGitHubAuth(config)` which stores the config at module level in `github.ts`. This avoids threading `config` through every `getGitHubClient()` call site.

### Auth Detection

On each `getGitHubClient()` call:
1. If the stored config has non-zero `app_id` and `installation_id` **and** a private key env var is present → use App auth
2. Else if `GITHUB_TOKEN` env var is set → use PAT (existing behavior, fully backward compatible)
3. Else → throw with a message listing both options

### Token Lifecycle

Installation tokens expire in ~1 hour. The cached token is refreshed automatically when it is within 5 minutes of expiry (lazy refresh on each `getGitHubAppToken()` call). At agent spawn time a fresh token is generated; this token is embedded in the MCP server env, the agent subprocess env, and the clone's git remote URL. All three share the same expiry horizon.

**Known limitation:** If an agent runs longer than ~1 hour, the embedded GitHub MCP server token and git remote token will expire. GitHub MCP calls and git push operations will fail after that point. This is accepted.

## Components

### 1. `src/lib/github-app-auth.ts` (new)

Handles all GitHub App credential logic. No new dependencies — uses Node's built-in `crypto` module for RS256 JWT signing.

**Exports:**
- `isAppAuthConfigured(config)` — returns `true` if `app_id` and `installation_id` are non-zero and at least one private key env var is present
- `getGitHubAppToken(config)` — returns a valid installation token string; refreshes automatically if within 5 minutes of expiry. Uses promise-based in-flight deduplication: if a refresh is already in progress (from a concurrent parallel agent spawn), additional callers await the same promise rather than issuing duplicate token requests.
- `resetAppAuthCache()` — clears cached token and any in-flight promise (used in tests)

**Internal functions:**
- `loadPrivateKey()` — reads from `GITHUB_APP_PRIVATE_KEY` env (inline PEM) first, then `GITHUB_APP_PRIVATE_KEY_PATH` env (path to `.pem` file). Throws if neither is set.
- `generateJWT(appId, privateKey)` — creates a signed RS256 JWT with the following exact structure:
  - Header: `{"alg":"RS256","typ":"JWT"}`
  - Payload: `{"iat": t-60, "exp": t+540, "iss": String(appId)}` where `t = Math.floor(Date.now() / 1000)` (Unix seconds). The `iss` claim **must** be a string — GitHub rejects numeric `iss`. The `iat` / `exp` values are integer seconds since epoch; using milliseconds would cause GitHub to reject the JWT with "expiration time is too far in the future".
  - Signing: `crypto.createSign('RSA-SHA256')` with the private key; output base64url-encoded
- `fetchInstallationToken(appId, installationId, privateKey)` — calls `POST /app/installations/{installationId}/access_tokens` with the JWT as `Authorization: Bearer {jwt}`. Wraps the call in `withRetry()` (same as all other GitHub API calls in this codebase) to handle transient 5xx errors. Returns `{ token: string, expiresAt: Date }`.

**Cached state:** `{ token: string, expiresAt: Date } | null` plus an `inFlight: Promise<...> | null` for deduplication — both module-level, cleared by `resetAppAuthCache()`.

### 2. `src/lib/config.ts` (modified)

Add two fields to `GithubConfig`:

```typescript
export interface GithubConfig {
  repo: string;
  automerge: boolean;
  app_id: number;          // 0 = not configured
  installation_id: number; // 0 = not configured
}
```

Defaults: `app_id: 0`, `installation_id: 0`.

### 3. `src/lib/github.ts` (modified)

**Add `initGitHubAuth(config: AutopilotConfig)`** — stores config at module level. Call this once at startup. This avoids threading config through every call site (`getPRStatus`, `getPRReviewInfo`, `enableAutoMerge`, `detectMergeMethod` — none of these need to change).

**`getGitHubClient()`** (unchanged signature):
- Reads from module-level config to detect App auth
- When App auth is active: call `getGitHubAppToken(config)`, store the returned token string alongside `_client`. On subsequent calls, if `getGitHubAppToken()` returns a different token (a refresh occurred), recreate the Octokit client with the new token.
- When PAT: existing behavior unchanged

**`resetClient()`** — also clears the stored token string and module-level config.

### 4. `src/lib/agent-config.ts` (modified)

**Token resolution at spawn time:**

```typescript
const githubToken = isAppAuthConfigured(config)
  ? await getGitHubAppToken(config)  // fresh installation token
  : process.env.GITHUB_TOKEN;        // PAT, passed through as-is
```

**`buildMcpServers(githubToken?: string)`** — switch GitHub MCP server:

```typescript
github: {
  type: "stdio",
  command: "npx",
  args: ["-y", "@github/github-mcp-server@latest", "stdio"],
  env: { GITHUB_TOKEN: githubToken }
}
```

**`buildAgentEnv(githubToken?: string)`** — inject `GITHUB_TOKEN` into agent subprocess env. When `githubToken` is provided it overrides whatever is in `process.env.GITHUB_TOKEN`.

**`buildQueryOptions(...)`** — add `githubToken?: string` to the `extras` parameter object and thread it through to `buildMcpServers()` and `buildAgentEnv()`.

**`SANDBOX_BASE_DOMAINS`** — remove `api.githubcopilot.com` since the Copilot-hosted MCP endpoint is no longer used. `api.github.com` and `github.com` remain (needed for the GitHub MCP stdio server's outbound calls and git operations).

### 5. `src/lib/sandbox-clone.ts` (modified)

`createClone()` gains an optional `githubToken?: string` parameter. When provided, after setting the origin remote URL, rewrite it to use token-based HTTPS auth:

```
https://x-access-token:{token}@github.com/{owner}/{repo}.git
```

This handles both SSH (`git@github.com:owner/repo.git`) and HTTPS remotes, ensuring `git push` works with the installation token.

**Security note:** The token is written in plaintext to the clone's `.git/config`. This is acceptable because clones are short-lived (deleted by `forceRemoveDir` after each agent run) and live under `.claude/clones/` which should not be world-readable. This matches the risk profile of an embedded PAT in a remote URL, which is the common CI/CD pattern.

## Configuration

`.autopilot.yml`:

```yaml
github:
  app_id: 123456
  installation_id: 987654
  repo: owner/repo    # optional, auto-detected if omitted
  automerge: false
```

Environment variables:

```bash
# Option A: inline PEM content
export GITHUB_APP_PRIVATE_KEY="-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEA...
-----END RSA PRIVATE KEY-----"

# Option B: path to .pem file
export GITHUB_APP_PRIVATE_KEY_PATH=/path/to/private-key.pem

# Legacy PAT (still works when app_id/installation_id are not set)
export GITHUB_TOKEN=ghp_...
```

## Backward Compatibility

No breaking changes. Existing users with `GITHUB_TOKEN` set and no `app_id`/`installation_id` in config continue to work exactly as before. Entry points that don't call `initGitHubAuth()` will fall through to `GITHUB_TOKEN` as before.

## Error Messages

- Missing private key when App auth fields are set: `"GitHub App auth is configured (app_id/installation_id) but no private key found. Set GITHUB_APP_PRIVATE_KEY or GITHUB_APP_PRIVATE_KEY_PATH."`
- Neither App auth nor PAT configured: `"No GitHub credentials found. Either set GITHUB_TOKEN (personal access token) or configure github.app_id + github.installation_id in .autopilot.yml with GITHUB_APP_PRIVATE_KEY / GITHUB_APP_PRIVATE_KEY_PATH."`

## Testing

- `github-app-auth.test.ts` — unit tests for:
  - JWT structure and claims (`alg`, `typ`, `iss` is string, `iat`/`exp` in seconds)
  - Token caching: cached token is reused before expiry window
  - Token refresh: token is refreshed when within 5 minutes of expiry
  - In-flight deduplication: concurrent calls during a refresh share one promise
  - Private key loading: inline PEM via `GITHUB_APP_PRIVATE_KEY`, file path via `GITHUB_APP_PRIVATE_KEY_PATH`, prefers inline over path, throws when neither set
  - `withRetry` is used for token fetch (transient error resilience)
- `github.test.ts` — auth detection branching; mock `getGitHubAppToken`; Octokit client is recreated when token changes
- `agent-config.test.ts` — resolved token flows into MCP server env and agent env; `buildQueryOptions` threads token through correctly
- `sandbox-clone.test.ts` — remote URL rewritten for SSH and HTTPS remotes when `githubToken` is provided; unchanged when not provided
