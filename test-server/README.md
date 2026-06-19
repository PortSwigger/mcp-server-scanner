# mcp-test-server

An intentionally vulnerable MCP (Model Context Protocol) server used as a test
target for the [Burp Suite MCP Server Scanner extension](../).

This project exposes deliberately unsafe tools (SQL injection, command
injection, path traversal, prompt injection, weak auth, etc.) so that the Burp
extension's scan checks can be exercised against realistic failure modes.

> Do not deploy this server anywhere reachable from an untrusted network.

## Install

Requires [`uv`](https://docs.astral.sh/uv/) and Python 3.11+.

```bash
cd test-server
uv sync
```

## Run

```bash
uv run mcp-test-server --help
```

The server listens on the configured host/port (default `0.0.0.0:8000`) and
speaks MCP over both Streamable HTTP (`/mcp`) and SSE (`/sse`). Point the Burp
extension's endpoint field at the URL it prints on startup.

## Develop

```bash
uv run pytest
uv run ruff check .
uv run mypy src
```

To list all registered tool/resource/prompt plugins without starting the server:

```bash
uv run mcp-test-server --list-plugins
```

---

## Fixture catalogue

The table below maps each fixture (handler, middleware, or CLI flag) to the
active scan check it exercises, plus the condition that triggers a finding and
the condition under which the check reports clean.

### Active scan checks

| Check class | Issue name | Vulnerable fixture | Vulnerable CLI flags | Clean (no-issue) CLI flags |
|---|---|---|---|---|
| `McpActiveUnauthenticatedToolDiscoveryCheck` | MCP Unauthenticated Tool Discovery | `broken-bearer` auth strategy | `--auth broken-bearer` | `--auth oauth` |
| `McpActiveAuthBypassCheck` | MCP Authentication Bypass | `broken-bearer` auth strategy | `--auth broken-bearer` | `--auth oauth` |
| `McpActiveHiddenMethodCheck` | MCP Hidden Method Exposed | `HiddenMethodsMiddleware` (default) | _(default — no flag needed)_ or `--hidden-methods enabled` | `--hidden-methods disabled` |
| `McpActiveDnsRebindingCheck` | MCP DNS Rebinding / MCP Origin Header Validation | DNS rebinding protection off (default) | _(default — no flag needed)_ or `--transport-security disabled` | `--transport-security enabled` |
| `McpActiveUnauthenticatedToolDiscoveryCheck` | MCP Unauthenticated Tool Discovery | No auth (default) | `--auth none` | `--auth oauth` |
| `McpActiveResourcePathTraversalCheck` | MCP Resource Path Traversal | `read_file` resource plugin (always registered) | `--auth none` | `--auth oauth` (returns 401) |
| `McpActiveToolArgumentPathTraversalCheck` | MCP Tool Argument Path Traversal | `read_file_tool` tool plugin | `--enable read_file_tool --auth none` | _(omit `read_file_tool` from `--enable`)_ or `--auth oauth` |
| `McpActiveOAuthTokenValidationCheck` | MCP OAuth Token Validation | JWT signature check disabled | `--auth oauth --oauth-skip-signature` | `--auth oauth` (strict, default) |
| `McpActiveOAuthMetadataSsrfCheck` | MCP OAuth Discovery Metadata Exposes Unsafe URLs | AS metadata overridden with cloud-metadata URLs | `--auth oauth --oauth-issuer-override http://169.254.169.254/iam` | `--auth none` (no OAuth discovery) |
| `McpActiveDcrMisconfigurationCheck` | MCP OAuth DCR Misconfiguration | `/register` open (unauthenticated DCR, default) | `--auth oauth` | `--auth oauth --oauth-dcr-strict` |
| `McpActiveToolArgumentRceCheck` | MCP Tool Argument Code Execution | `ping_host` tool plugin (shell injection) or `format_quote` (eval injection) | `--enable ping_host --auth none` or `--enable format_quote --auth none` | No fixture available in standalone E2E — requires Burp Collaborator; covered by unit tests only |

### Discovery Content Scanner

The content scanner runs at connect time (not via Burp's active scan pipeline)
and scans tool/resource/prompt descriptions and `serverInfo` for secrets and
unsafe icon URIs. The table below maps content fixtures to the credential
patterns they exercise.

| Plugin / fixture | Type | Triggered rules |
|---|---|---|
| `leaky_describe` | Tool | AWS key (`AKIAQ7777PYTYINTERNAL`), JWT, GitHub PAT, Slack token, Anthropic key, Google API key, Stripe key, email |
| `leaky_internal_db` | Resource (`internal://192.168.1.10/analytics`) | Azure connection string, GCP service account key, private IP |
| `leaky_payment_email` | Prompt | SSH private key, PGP private key, credit card number |
| `poisoned_icons_demo` | Tool | Unsafe icon URI (`javascript:`, plain-HTTP, `image/svg+xml`, oversized `sizes`) |
| `poisoned_icons_resource` | Resource (`poisoned://icons-resource`) | Unsafe icon URI (same as above, on a resource) |
| `poisoned_icons_prompt` | Prompt | Unsafe icon URI (same as above, on a prompt) |
| `app.py` `_SERVER_INFO_ICONS` | `serverInfo.icons` (always active) | Unsafe icon URI (`javascript:alert('serverInfo')`, plain-HTTP) |

### Response Content Scanner

The response content scanner is a passive Burp scan check that inspects the
runtime output of `tools/call`, `resources/read`, and `prompts/get` responses
for high-precision secrets (cloud keys, tokens, private keys). Unlike the
discovery content scanner it runs on the values a tool actually returns to the
caller, not on discovery metadata.

| Plugin / fixture | Type | Triggered rules | Vulnerable CLI flags |
|---|---|---|---|
| `deploy_status` | Tool | AWS key (`AKIAQ7777PYTYINTERNAL`), GitHub PAT (`ghp_5tQk9XnVbZmRfHsCwLpYJgAaBcDeFgHiJk23`) in `tools/call` output | `--enable deploy_status --auth none` |

---

## Example invocations

### Minimal — no auth, all default plugins

```bash
uv run mcp-test-server --host 127.0.0.1 --port 8000
```

Connect URL: `http://127.0.0.1:8000/mcp`
Transport: Streamable HTTP
Auth: none

Exercises: `McpActiveUnauthenticatedToolDiscoveryCheck`, `McpActiveHiddenMethodCheck` (default),
`McpActiveDnsRebindingCheck` (default), `McpActiveResourcePathTraversalCheck`,
Discovery Content Scanner (leaky descriptions, poisoned icons, serverInfo icons).

---

### Auth bypass — broken bearer

```bash
uv run mcp-test-server --host 127.0.0.1 --port 8000 --auth broken-bearer
```

Connect URL: `http://127.0.0.1:8000/mcp`
Transport: Streamable HTTP
Auth: Bearer token (any value accepted)

Exercises: `McpActiveUnauthenticatedToolDiscoveryCheck`, `McpActiveAuthBypassCheck`.

---

### Tool argument path traversal

```bash
uv run mcp-test-server --host 127.0.0.1 --port 8000 --auth none --enable read_file_tool
```

Connect URL: `http://127.0.0.1:8000/mcp`
Transport: Streamable HTTP
Auth: none

Exercises: `McpActiveToolArgumentPathTraversalCheck` (unsandboxed `read_file_tool`).

---

### Resource path traversal

```bash
uv run mcp-test-server --host 127.0.0.1 --port 8000 --auth none
```

The `read_file` resource template (`file:///{path}`) is always registered.

Exercises: `McpActiveResourcePathTraversalCheck`.

---

### Tool argument RCE (output-based; Collaborator not required)

```bash
uv run mcp-test-server --host 127.0.0.1 --port 8000 --auth none --enable ping_host
```

Connect URL: `http://127.0.0.1:8000/mcp`
Transport: Streamable HTTP
Auth: none

The `ping_host` tool passes the caller-supplied `host` argument directly to
`subprocess.run(..., shell=True)`. Output-based injection payloads (`; id`,
`` `id` ``) reflect in the response. Time-based detection requires raising
`_TIMEOUT_SECONDS` in `vulns/ping_host.py` (default 2 s is deliberately below
Burp's 15.75 s delta threshold).

Note: `McpActiveToolArgumentRceCheck` relies on Burp Collaborator for
out-of-band detection and cannot run in a standalone JUnit process. Use Burp's
scanner against this fixture for end-to-end Collaborator-backed testing.

Alternative: `--enable format_quote` starts the `format_quote` tool which runs
`eval()` on the caller-supplied `format` argument.

---

### DNS rebinding protection — vulnerable (default)

```bash
uv run mcp-test-server --host 127.0.0.1 --port 8000 --transport-security disabled
```

Exercises: `McpActiveDnsRebindingCheck` (origin/Host validation absent).

### DNS rebinding protection — clean baseline

```bash
uv run mcp-test-server --host 127.0.0.1 --port 8000 --transport-security enabled
```

The server validates `Host` and `Origin` headers against the loopback allowlist.
`McpActiveDnsRebindingCheck` should not raise an issue for the origin category.

---

### Hidden methods — clean baseline

```bash
uv run mcp-test-server --host 127.0.0.1 --port 8000 --hidden-methods disabled
```

`StrictMethodMiddleware` rejects any non-standard method with JSON-RPC `-32601`.
`McpActiveHiddenMethodCheck` should find no hidden methods.

---

### OAuth — strict (clean baseline for most OAuth checks)

```bash
uv run mcp-test-server --host 127.0.0.1 --port 8000 --auth oauth
```

Connect URL: `http://127.0.0.1:8000/mcp`
Transport: Streamable HTTP
Auth: OAuth 2.1 (PKCE, dynamic client registration enabled by default)

Exercises (vulnerable): `McpActiveDcrMisconfigurationCheck` (open `/register`
with no `--oauth-dcr-strict`).
Clean baseline for: `McpActiveUnauthenticatedToolDiscoveryCheck`,
`McpActiveAuthBypassCheck`, `McpActiveResourcePathTraversalCheck`.

---

### OAuth — token validation disabled (JWT signature skip)

```bash
uv run mcp-test-server --host 127.0.0.1 --port 8000 --auth oauth --oauth-skip-signature
```

Exercises: `McpActiveOAuthTokenValidationCheck` (server accepts attacker-signed JWTs).

Other token-weakening flags (combinable):
- `--oauth-accept-alg-none` — accepts `alg: none` JWTs
- `--oauth-skip-audience` — skips audience claim validation
- `--oauth-skip-issuer` — skips issuer claim validation
- `--oauth-skip-expiry` — skips expiry claim validation

---

### OAuth — AS metadata SSRF fixture

```bash
uv run mcp-test-server --host 127.0.0.1 --port 8000 \
  --auth oauth \
  --oauth-issuer-override http://169.254.169.254/iam
```

`/.well-known/oauth-authorization-server` advertises cloud-metadata URLs for
`issuer`, `authorization_endpoint`, etc.

Exercises: `McpActiveOAuthMetadataSsrfCheck`.

---

### OAuth — test-only token mint endpoint

**TEST FIXTURE — DO NOT USE IN PRODUCTION.**

```bash
uv run mcp-test-server --host 127.0.0.1 --port 8000 --auth oauth --oauth-test-mint-endpoint
```

Exposes `POST /test-only/mint-token` (no authentication) which returns a
signer-issued RS256 JWT in `{"access_token": "..."}`. Body is optional JSON
with `subject` (default `"test"`), `scopes` (default `[]`), and `expires_in`
(default 60 s). Used by the Java integration tests to drive the strict-OAuth
clean baselines without running the full authorization-code flow.

The endpoint is registered only when this flag is set; production-shaped
`--auth oauth` runs without the flag never expose it.

---

### OAuth — DCR strict (clean baseline for DCR check)

```bash
uv run mcp-test-server --host 127.0.0.1 --port 8000 --auth oauth --oauth-dcr-strict
```

`/register` requires a Bearer token and validates `redirect_uris`.
`McpActiveDcrMisconfigurationCheck` should not fire.

---

### SSE transport

Both Streamable HTTP (`/mcp`) and SSE (`/sse`) are always available. To use the
SSE transport, point the extension at:

```
http://127.0.0.1:8000/sse
```

and select SSE as the transport in the extension UI. All fixture flags above
apply regardless of transport.

---

### Selectively enabling or disabling plugins

Use `--enable PLUGIN_NAME` to start the server with only the named plugins
(repeatable). Use `--disable PLUGIN_NAME` to start with all plugins except the
named ones. The two flags are mutually exclusive.

```bash
# Only the path-traversal tools — minimise noise
uv run mcp-test-server --enable read_file_tool --enable fetch_url --auth none

# All plugins except the leaky-description fixture
uv run mcp-test-server --disable leaky_describe --auth none
```

Plugin names (pass to `--enable` / `--disable`):

| Plugin name | Module | Kind |
|---|---|---|
| `deploy_status` | `vulns/leaky_tool_output.py` | Tool |
| `format_quote` | `vulns/eval_format.py` | Tool |
| `fetch_url` | `vulns/fetch_url.py` | Tool |
| `leaky_describe` | `vulns/leaky_descriptions.py` | Tool |
| `ping_host` | `vulns/ping_host.py` | Tool |
| `poisoned_icons_demo` | `vulns/poisoned_icons_tool.py` | Tool |
| `query_user` | `vulns/query_user.py` | Tool |
| `read_file_tool` | `vulns/read_file_tool.py` | Tool |
| `user_info` | `vulns/user_info.py` | Tool |
| `read_file` | `vulns/read_file.py` | Resource (`file:///{path}`) |
| `leaky_internal_db` | `vulns/leaky_resource.py` | Resource |
| `poisoned_icons_resource` | `vulns/poisoned_icons_resource.py` | Resource |
| `changelog` | `vulns/sample_changelog.py` | Resource |
| `health` | `vulns/sample_health.py` | Resource |
| `readme` | `vulns/sample_readme.py` | Resource |
| `user_profile` | `vulns/sample_user_profile.py` | Resource (`user://profile/{id}`) |
| `users_sample` | `vulns/sample_users.py` | Resource |
| `leaky_payment_email` | `vulns/leaky_prompt.py` | Prompt |
| `poisoned_icons_prompt` | `vulns/poisoned_icons_prompt.py` | Prompt |
| `code_review` | `vulns/sample_prompt_code_review.py` | Prompt |
| `summarize` | `vulns/sample_prompt_summarize.py` | Prompt |

Note: `--enable` / `--disable` filter only tool plugins. Resource and prompt
plugins are always registered regardless of these flags (they are wired via
`registry.register_resources_all` and `registry.register_prompts_all`).
