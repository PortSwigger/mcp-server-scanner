# MCP Server Scanner Extension

A Burp Suite extension for security-testing [Model Context Protocol](https://modelcontextprotocol.io) servers.

Discovers MCP tools, resources, resource templates, and prompts, builds JSON-RPC 2.0 requests with fuzzable insertion points, and runs them through Burp's active and passive scanners.

> **Requires Burp Suite Professional.** Every check is driven by Burp's Scanner (active and passive audits), which is not present in Burp Community Edition. The extension loads in Community but cannot scan — discovery may work, but no audit checks will run. Burp Collaborator (also Professional-only) is additionally required for the out-of-band RCE check.

## Features

- **Transports:** Streamable HTTP and SSE (with a local proxy that lets Burp's scanner consume `text/event-stream`).
- **Auth:** None, Bearer token, custom header, and OAuth 2.1 (PKCE + dynamic client registration, RFC 8414 / RFC 9728 discovery).
- **Active checks:** unauthenticated tool discovery, auth bypass, hidden methods, resource path traversal, OAuth token validation, DNS rebinding, OAuth metadata SSRF, DCR misconfiguration, OAuth consent-page reflected XSS, tool-argument path traversal, tool-argument RCE (Collaborator-backed).
- **Content checks:** scans discovered metadata for leaked secrets (AWS, GitHub, Slack, Stripe, GCP, JWT, SSH/PGP private keys, etc.) and unsafe icon URLs.

Aimed at MCP server **operators** auditing their own deployments.

## Build

```bash
./gradlew shadowJar
```

Output: `build/libs/mcp-server-scanner-extension-0.1.0-all.jar`.

Requires Java 17.

## Install

In Burp: **Extensions → Installed → Add → Java**, then select the fat JAR above.

Open the **MCP Server Scanner** tab, configure the server endpoint and auth, and connect.

## Test server

A deliberately-vulnerable MCP server lives under `test-server/` (uv-managed, Python 3.11+). Use it to exercise checks end-to-end:

```bash
cd test-server
uv run server.py
```

## Development

```bash
./gradlew test                                    # run all tests
./gradlew test --tests McpRequestDetectorTest     # single class
./gradlew dependencies --write-locks              # regenerate lockfile
```

See [`CLAUDE.md`](./CLAUDE.md) for the architecture overview.

## Threat model and scope

Use this extension only on MCP servers you own or have written authorization to test.

Scans are intrusive: they send malformed JSON-RPC requests, fuzz tool arguments (which may invoke side-effectful tools on the target server), trigger Burp Collaborator out-of-band interactions, and may briefly stall the target server under load.

This tool is designed for MCP server **operators** auditing their own deployments. It is not designed for opportunistic scans against MCP servers you do not control.

## Known limitations

- **Burp Suite Professional required**: every check runs through Burp's Scanner (active/passive audits), which Community Edition does not include. In Community the extension loads and can connect/discover, but no scan checks will run. There is no Community-compatible mode.
- **Collaborator-backed checks**: within Professional, `McpActiveToolArgumentRceCheck` additionally requires Burp Collaborator for out-of-band detection. It silently degrades and produces no findings if Collaborator is unavailable.
- **SSE proxy port**: the local SSE proxy binds to an ephemeral loopback port. Firewall or network policies that block loopback traffic will break SSE-transport scans.
- **OAuth callback port**: the OAuth callback listener defaults to an ephemeral port (port 0). If your authorization server requires strict redirect-URI pre-registration, set a fixed callback port in the OAuth section before initiating the flow.
- **Project file sensitivity**: tool toggles and OAuth credentials are persisted in the Burp project file. Treat the project file as sensitive and restrict access accordingly.
- **Auth-bypass check on SSE transport**: on SSE, per-request message POSTs are correlated to the already-opened SSE stream by the endpoint URL rather than by a per-request auth header, so the auth-bypass probe cannot send a fully unauthenticated request the way it does on Streamable HTTP. On SSE the check demonstrates that a tool executes within an already-authenticated session; it does not by itself prove that per-request authentication is absent. The auth-bypass check is fully reliable on Streamable HTTP transport.

## Troubleshooting

**OAuth 401 loops** — usually a clock-skew or audience-mismatch issue. Verify that `Mcp-Session-Id` is round-tripping through the proxy and that the token audience matches the resource server's expected value.

**SSE handshake hangs** — confirm the local proxy port is reachable from Burp's scanner. Check the Logger sub-tab for proxy startup errors or connection failures.

**`tools/list` returns empty** — the server may require `Mcp-Session-Id` from a prior `initialize` handshake. The extension performs this automatically, but a malformed `initialize` response (non-JSON body or missing `protocolVersion`) will leave the session unset and subsequent requests will fail silently.

**JAR loads but no tab appears** — open Burp's **Extender** output panel and look for a stack trace. The most common causes are a Java version mismatch (requires Java 17+) or a conflicting dependency already loaded by another extension.
