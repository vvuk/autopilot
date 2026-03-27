import { afterEach, beforeEach, describe, expect, mock, test } from "bun:test";

let mockCachedAppToken: string | null = null;

mock.module("./github-app-auth", () => ({
  getCachedAppToken: () => mockCachedAppToken,
}));

import { buildAgentEnv, buildMcpServers } from "./agent-config";

describe("buildMcpServers", () => {
  let savedLinearApiKey: string | undefined;

  beforeEach(() => {
    savedLinearApiKey = process.env.LINEAR_API_KEY;
    mockCachedAppToken = null;
  });

  afterEach(() => {
    if (savedLinearApiKey === undefined) {
      delete process.env.LINEAR_API_KEY;
    } else {
      process.env.LINEAR_API_KEY = savedLinearApiKey;
    }
  });

  test("uses LINEAR_API_KEY env var when no token is passed", () => {
    process.env.LINEAR_API_KEY = "lin_api_test_key";
    const servers = buildMcpServers();
    const linear = servers.linear as { headers: { Authorization: string } };
    expect(linear.headers.Authorization).toBe("Bearer lin_api_test_key");
  });

  test("uses provided token instead of LINEAR_API_KEY", () => {
    process.env.LINEAR_API_KEY = "lin_api_env_key";
    const servers = buildMcpServers("lin_api_passed_token");
    const linear = servers.linear as { headers: { Authorization: string } };
    expect(linear.headers.Authorization).toBe("Bearer lin_api_passed_token");
  });

  test("throws when no token passed and LINEAR_API_KEY is not set", () => {
    delete process.env.LINEAR_API_KEY;
    expect(() => buildMcpServers()).toThrow("No Linear token available");
  });

  test("throws when empty string token is passed and LINEAR_API_KEY is not set", () => {
    delete process.env.LINEAR_API_KEY;
    // Passing undefined explicitly — same as calling without args
    expect(() => buildMcpServers(undefined)).toThrow(
      "No Linear token available",
    );
  });

  test("uses provided token even when LINEAR_API_KEY is not set", () => {
    delete process.env.LINEAR_API_KEY;
    const servers = buildMcpServers("oauth_token_xyz");
    const linear = servers.linear as { headers: { Authorization: string } };
    expect(linear.headers.Authorization).toBe("Bearer oauth_token_xyz");
  });

  test("returns github and autopilot servers alongside linear", () => {
    process.env.LINEAR_API_KEY = "lin_api_test";
    const servers = buildMcpServers();
    expect(servers.linear).toBeDefined();
    expect(servers.github).toBeDefined();
    expect(servers.autopilot).toBeDefined();
  });
});

describe("buildMcpServers — github MCP server", () => {
  let savedLinearKey: string | undefined;
  let savedGithubToken: string | undefined;

  beforeEach(() => {
    savedLinearKey = process.env.LINEAR_API_KEY;
    savedGithubToken = process.env.GITHUB_TOKEN;
    process.env.LINEAR_API_KEY = "lin_test";
    mockCachedAppToken = null;
  });

  afterEach(() => {
    if (savedLinearKey === undefined) delete process.env.LINEAR_API_KEY;
    else process.env.LINEAR_API_KEY = savedLinearKey;
    if (savedGithubToken === undefined) delete process.env.GITHUB_TOKEN;
    else process.env.GITHUB_TOKEN = savedGithubToken;
  });

  test("github MCP server is stdio type pointing to github-mcp-server", () => {
    const servers = buildMcpServers();
    const gh = servers.github as {
      type: string;
      command: string;
      args: string[];
    };
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

  test("github MCP server env uses cached App token when available", () => {
    mockCachedAppToken = "ghs_app_token";
    process.env.GITHUB_TOKEN = "ghp_should_not_use";
    const servers = buildMcpServers();
    const gh = servers.github as { env: { GITHUB_TOKEN: string } };
    expect(gh.env.GITHUB_TOKEN).toBe("ghs_app_token");
  });
});

describe("buildAgentEnv — github token", () => {
  let savedGithubToken: string | undefined;

  beforeEach(() => {
    savedGithubToken = process.env.GITHUB_TOKEN;
    mockCachedAppToken = null;
  });

  afterEach(() => {
    if (savedGithubToken === undefined) delete process.env.GITHUB_TOKEN;
    else process.env.GITHUB_TOKEN = savedGithubToken;
  });

  test("includes GITHUB_TOKEN from env when set", () => {
    process.env.GITHUB_TOKEN = "ghp_in_env";
    const env = buildAgentEnv();
    expect(env.GITHUB_TOKEN).toBe("ghp_in_env");
  });

  test("GITHUB_TOKEN is absent when env var is not set and no App token", () => {
    delete process.env.GITHUB_TOKEN;
    mockCachedAppToken = null;
    const env = buildAgentEnv();
    expect(env.GITHUB_TOKEN).toBeUndefined();
  });

  test("GITHUB_TOKEN uses cached App token when available", () => {
    mockCachedAppToken = "ghs_cached";
    delete process.env.GITHUB_TOKEN;
    const env = buildAgentEnv();
    expect(env.GITHUB_TOKEN).toBe("ghs_cached");
  });

  test("cached App token overrides GITHUB_TOKEN env var", () => {
    process.env.GITHUB_TOKEN = "ghp_pat";
    mockCachedAppToken = "ghs_app";
    const env = buildAgentEnv();
    expect(env.GITHUB_TOKEN).toBe("ghs_app");
  });
});
