import { Octokit } from "octokit";
import type { AutopilotConfig } from "./config";
import {
  getCachedAppToken,
  getGitHubAppToken,
  isAppAuthConfigured,
} from "./github-app-auth";
import { info, warn } from "./logger";
import { withRetry } from "./retry";

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
    info(`GitHub App auth active (app_id: ${config.github.app_id})`);
  } else {
    info(`GitHub user token auth`);
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
    if (!appToken) {
      throw new Error(
        "GitHub App auth is configured but the token cache is empty. " +
          "Ensure initGitHubAuth() was called at startup.",
      );
    }
    if (_client && _clientToken === appToken) return _client;
    _client = new Octokit({ auth: appToken });
    _clientToken = appToken;
    return _client;
  }

  const token = process.env.GITHUB_TOKEN;
  if (!token) {
    throw new Error(
      "No GitHub credentials found. Set GITHUB_TOKEN (personal access token) or " +
        "configure github.app_id + github.installation_id in .autopilot.yml with " +
        "GITHUB_APP_PRIVATE_KEY / GITHUB_APP_PRIVATE_KEY_PATH.",
    );
  }

  if (_client && !_clientToken) return _client;
  _client = new Octokit({ auth: token });
  _clientToken = null;
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

/**
 * Detect owner/repo from git remote origin, with config override.
 * Supports both HTTPS and SSH remote URLs.
 */
export function detectRepo(
  projectPath: string,
  configOverride?: string,
): { owner: string; repo: string } {
  if (configOverride) {
    const [owner, repo] = configOverride.split("/");
    if (!owner || !repo) {
      throw new Error(
        `Invalid github.repo config: "${configOverride}" — expected "owner/repo"`,
      );
    }
    return { owner, repo };
  }

  const result = Bun.spawnSync(
    ["git", "-C", projectPath, "remote", "get-url", "origin"],
    { stdout: "pipe", stderr: "pipe" },
  );
  if (result.exitCode !== 0) {
    throw new Error(
      `Failed to detect git remote origin in ${projectPath}. ` +
        "Set github.repo in .autopilot.yml instead.",
    );
  }

  const url = result.stdout.toString().trim();

  // HTTPS: https://github.com/owner/repo.git
  const httpsMatch = url.match(/github\.com\/([^/]+)\/([^/.]+)/);
  if (httpsMatch) {
    return { owner: httpsMatch[1], repo: httpsMatch[2] };
  }

  // SSH: git@github.com:owner/repo.git
  const sshMatch = url.match(/github\.com:([^/]+)\/([^/.]+)/);
  if (sshMatch) {
    return { owner: sshMatch[1], repo: sshMatch[2] };
  }

  throw new Error(
    `Could not parse owner/repo from remote URL: "${url}". ` +
      "Set github.repo in .autopilot.yml instead.",
  );
}

export interface PRStatus {
  merged: boolean;
  draft: boolean;
  mergeable: boolean | null;
  branch: string;
  ciStatus: "success" | "failure" | "pending";
  ciDetails: string;
}

/**
 * Get the merge and CI status of a PR.
 * Combines both legacy Status API and Checks API for full coverage.
 * Treats mergeable === null as pending (GitHub computes async).
 * Retries on transient errors (429, 5xx, network) up to 3 times.
 */
export async function getPRStatus(
  owner: string,
  repo: string,
  prNumber: number,
): Promise<PRStatus> {
  const octokit = getGitHubClient();

  const { data: pr } = await withRetry(
    () => octokit.rest.pulls.get({ owner, repo, pull_number: prNumber }),
    `getPR #${prNumber}`,
  );

  if (pr.merged) {
    return {
      merged: true,
      draft: false,
      mergeable: null,
      branch: pr.head.ref,
      ciStatus: "success",
      ciDetails: "",
    };
  }

  const sha = pr.head.sha;

  const { data } = await withRetry(
    () => octokit.rest.checks.listForRef({ owner, repo, ref: sha }),
    `getChecks #${prNumber}`,
  );
  const checks = data.check_runs;

  // Only report failure once all checks have finished — otherwise a
  // fast-failing check would trigger a fixer while slower checks still run.
  const allComplete = checks.every((c) => c.status === "completed");

  let ciStatus: PRStatus["ciStatus"] = "pending";
  const failureDetails: string[] = [];

  if (checks.length === 0 || !allComplete) {
    ciStatus = "pending";
  } else {
    const hasFailed = checks.some(
      (c) => c.conclusion === "failure" || c.conclusion === "timed_out",
    );

    if (hasFailed) {
      ciStatus = "failure";
      for (const check of checks) {
        if (
          check.conclusion === "failure" ||
          check.conclusion === "timed_out"
        ) {
          failureDetails.push(`${check.name}: ${check.conclusion}`);
        }
      }
    } else {
      ciStatus = "success";
    }
  }

  return {
    merged: false,
    draft: pr.draft ?? false,
    mergeable: pr.mergeable,
    branch: pr.head.ref,
    ciStatus,
    ciDetails: failureDetails.join("\n"),
  };
}

/**
 * Check if a PR has an unacknowledged "autopilot: keep going" comment.
 * Looks for issue comments whose body is exactly "autopilot: keep going"
 * (trimmed, case-insensitive) that do NOT already have a +1 reaction.
 * If found, adds a +1 reaction and returns true (meaning "reset fixer attempts").
 */
export async function checkKeepGoingSignal(
  owner: string,
  repo: string,
  prNumber: number,
): Promise<boolean> {
  const octokit = getGitHubClient();

  const { data: comments } = await withRetry(
    () =>
      octokit.rest.issues.listComments({
        owner,
        repo,
        issue_number: prNumber,
      }),
    `listComments #${prNumber}`,
  );

  for (const comment of comments) {
    if (comment.body?.trim().toLowerCase() !== "autopilot: keep going") {
      continue;
    }

    // Check if we already acknowledged this comment with a +1
    const { data: reactions } = await withRetry(
      () =>
        octokit.rest.reactions.listForIssueComment({
          owner,
          repo,
          comment_id: comment.id,
        }),
      `listReactions comment ${comment.id}`,
    );

    const hasThumbsUp = reactions.some((r) => r.content === "+1");
    if (hasThumbsUp) {
      continue;
    }

    // Acknowledge and signal reset
    await withRetry(
      () =>
        octokit.rest.reactions.createForIssueComment({
          owner,
          repo,
          comment_id: comment.id,
          content: "+1",
        }),
      `reactToComment ${comment.id}`,
    );
    return true;
  }

  return false;
}

/**
 * Search GitHub for a user by email address.
 * Returns the GitHub login (username) if found, null otherwise.
 */
export async function findGitHubUserByEmail(
  email: string,
): Promise<string | null> {
  const octokit = getGitHubClient();
  try {
    const { data } = await withRetry(
      () => octokit.rest.search.users({ q: `${email} in:email` }),
      `searchUserByEmail ${email}`,
    );
    if (data.total_count > 0 && data.items[0]) {
      return data.items[0].login;
    }
    return null;
  } catch {
    return null;
  }
}

/**
 * Request a review on a PR from a GitHub user identified by email.
 * Searches for the GitHub user, then requests review if found.
 * Returns a human-readable result message.
 */
export async function requestReviewByEmail(
  owner: string,
  repo: string,
  prNumber: number,
  email: string,
): Promise<string> {
  const login = await findGitHubUserByEmail(email);
  if (!login) {
    return `No GitHub user found for email ${email} — skipping review request.`;
  }

  const octokit = getGitHubClient();
  try {
    await withRetry(
      () =>
        octokit.rest.pulls.requestReviewers({
          owner,
          repo,
          pull_number: prNumber,
          reviewers: [login],
        }),
      `requestReviewers #${prNumber}`,
    );
    return `Requested review from @${login} (${email}) on PR #${prNumber}.`;
  } catch (e: unknown) {
    const msg = e instanceof Error ? e.message : String(e);
    return `Found GitHub user @${login} for ${email}, but failed to request review: ${msg}`;
  }
}

export interface PRReviewInfo {
  hasChangesRequested: boolean;
  /** ID of the latest CHANGES_REQUESTED review, used for dedup. Null if none. */
  latestChangesRequestedReviewId: string | null;
  /** ID of the latest inline review comment, used for dedup. Null if none. */
  latestReviewCommentId: string | null;
  /** ID of the latest PR-level (issue) comment, used for dedup. Null if none. */
  latestIssueCommentId: string | null;
  /** Formatted inline review comments for use in prompts. */
  reviewComments: string;
  /** Formatted reviewer summary bodies for use in prompts. */
  reviewSummaries: string;
  /** Formatted PR-level (non-inline) comments for use in prompts. */
  prComments: string;
}

/**
 * Get review status for a PR: CHANGES_REQUESTED state and comment text.
 * Considers only the latest review per user to handle re-reviews correctly.
 */
export async function getPRReviewInfo(
  owner: string,
  repo: string,
  prNumber: number,
): Promise<PRReviewInfo> {
  const octokit = getGitHubClient();

  const [{ data: reviews }, { data: comments }, { data: issueComments }] =
    await Promise.all([
      withRetry(
        () =>
          octokit.rest.pulls.listReviews({
            owner,
            repo,
            pull_number: prNumber,
          }),
        `listReviews #${prNumber}`,
      ),
      withRetry(
        () =>
          octokit.rest.pulls.listReviewComments({
            owner,
            repo,
            pull_number: prNumber,
          }),
        `listReviewComments #${prNumber}`,
      ),
      withRetry(
        () =>
          octokit.rest.issues.listComments({
            owner,
            repo,
            issue_number: prNumber,
          }),
        `listIssueComments #${prNumber}`,
      ),
    ]);

  // Determine the latest review per user (handles re-reviews)
  const latestByUser = new Map<string, (typeof reviews)[0]>();
  for (const review of reviews) {
    const userId = review.user?.login ?? "unknown";
    const existing = latestByUser.get(userId);
    const reviewTime = review.submitted_at
      ? new Date(review.submitted_at).getTime()
      : 0;
    const existingTime = existing?.submitted_at
      ? new Date(existing.submitted_at).getTime()
      : 0;
    if (!existing || reviewTime > existingTime) {
      latestByUser.set(userId, review);
    }
  }

  // Find latest reviews with CHANGES_REQUESTED from each user
  const changesRequestedReviews = [...latestByUser.values()].filter(
    (r) => r.state === "CHANGES_REQUESTED",
  );

  const hasChangesRequested = changesRequestedReviews.length > 0;

  // Pick the most recently submitted CHANGES_REQUESTED review for dedup
  let latestChangesRequestedReviewId: string | null = null;
  if (hasChangesRequested) {
    const latest = changesRequestedReviews.reduce((a, b) => {
      const aTime = a.submitted_at ? new Date(a.submitted_at).getTime() : 0;
      const bTime = b.submitted_at ? new Date(b.submitted_at).getTime() : 0;
      return aTime >= bTime ? a : b;
    });
    latestChangesRequestedReviewId = String(latest.id);
  }

  // Format review summaries (body text from CHANGES_REQUESTED and COMMENTED reviews)
  const feedbackReviews = [...latestByUser.values()].filter(
    (r) => r.state === "CHANGES_REQUESTED" || r.state === "COMMENTED",
  );
  const reviewSummaries = feedbackReviews
    .filter((r) => r.body)
    .map((r) => `Reviewer ${r.user?.login ?? "unknown"}: ${r.body}`)
    .join("\n\n");

  // Format inline review comments
  const reviewComments = comments
    .map(
      (c) =>
        `File: ${c.path} (line ${c.line ?? c.original_line ?? "?"})\nReviewer: ${c.user?.login ?? "unknown"}\nComment: ${c.body}`,
    )
    .join("\n\n");

  // Track latest inline review comment ID for dedup
  let latestReviewCommentId: string | null = null;
  if (comments.length > 0) {
    const latest = comments.reduce((a, b) => (a.id > b.id ? a : b));
    latestReviewCommentId = String(latest.id);
  }

  // Find the latest PR-level (issue) comment by ID (IDs are monotonically increasing)
  let latestIssueCommentId: string | null = null;
  if (issueComments.length > 0) {
    const latest = issueComments.reduce((a, b) => (a.id > b.id ? a : b));
    latestIssueCommentId = String(latest.id);
  }

  const prComments = issueComments
    .map((c) => `Comment by ${c.user?.login ?? "unknown"}: ${c.body}`)
    .join("\n\n");

  return {
    hasChangesRequested,
    latestChangesRequestedReviewId,
    latestReviewCommentId,
    latestIssueCommentId,
    reviewComments,
    reviewSummaries,
    prComments,
  };
}

/**
 * Detect which merge method the repo allows.
 * Priority: MERGE > SQUASH > REBASE (matches `gh` CLI behavior).
 */
async function detectMergeMethod(
  owner: string,
  repo: string,
): Promise<"MERGE" | "SQUASH" | "REBASE"> {
  const octokit = getGitHubClient();
  const { data } = await withRetry(
    () => octokit.rest.repos.get({ owner, repo }),
    `getRepo ${owner}/${repo}`,
  );
  if (data.allow_merge_commit) return "MERGE";
  if (data.allow_squash_merge) return "SQUASH";
  if (data.allow_rebase_merge) return "REBASE";
  return "MERGE"; // fallback
}

/**
 * Enable auto-merge on a PR via the GitHub GraphQL API.
 * Auto-detects the repo's allowed merge method.
 * Returns a success/failure message suitable for tool output.
 */
export async function enableAutoMerge(
  owner: string,
  repo: string,
  prNumber: number,
): Promise<string> {
  const octokit = getGitHubClient();

  const [{ data: pr }, mergeMethod] = await Promise.all([
    withRetry(
      () => octokit.rest.pulls.get({ owner, repo, pull_number: prNumber }),
      `getPR #${prNumber}`,
    ),
    detectMergeMethod(owner, repo),
  ]);

  try {
    await withRetry(
      () =>
        octokit.graphql(
          `mutation($prId: ID!, $mergeMethod: PullRequestMergeMethod!) {
            enablePullRequestAutoMerge(input: { pullRequestId: $prId, mergeMethod: $mergeMethod }) {
              pullRequest { autoMergeRequest { enabledAt } }
            }
          }`,
          { prId: pr.node_id, mergeMethod },
        ),
      `enableAutoMerge #${prNumber}`,
    );
    return `Auto-merge (${mergeMethod.toLowerCase()}) enabled for PR #${prNumber}`;
  } catch (e: unknown) {
    const msg = e instanceof Error ? e.message : String(e);
    warn(`Failed to enable auto-merge for PR #${prNumber}: ${msg}`);
    return `Failed to enable auto-merge: ${msg}`;
  }
}
