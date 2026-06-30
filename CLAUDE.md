# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What This Is

A Burp Suite extension that security-tests MCP (Model Context Protocol) servers. It discovers MCP tools, resources, resource templates, and prompts, builds JSON-RPC 2.0 requests with fuzzable insertion points, and runs Burp's active/passive scanner against them. Supports Streamable HTTP and SSE transports with pluggable authentication (including OAuth 2.1 with PKCE and dynamic client registration).

**Burp Suite Professional only.** Every check is driven by Burp's Scanner (active/passive audits), which Community Edition does not include — the extension loads in Community but cannot scan. Collaborator (also Pro-only) is additionally required for the out-of-band RCE check.

## Build & Test Commands

```bash
./gradlew build                  # Compile + test
./gradlew test                   # Run all tests
./gradlew test --tests McpRequestDetectorTest  # Single test class
./gradlew shadowJar              # Build fat JAR for Burp (build/libs/mcp-server-scanner-extension-0.1.0-all.jar)
./gradlew dependencies --write-locks  # Regenerate gradle.lockfile after changing dependencies
```

**Always run `./gradlew shadowJar` after code changes** — the user loads the fat JAR into Burp.

Dependency resolution is locked via `gradle.lockfile`. If you add or bump a dependency in `build.gradle` and the build fails with a lockfile mismatch, run `./gradlew dependencies --write-locks` to regenerate the lockfile, then commit it.

Java 17 toolchain.

## Architecture

**Entry point:** `McpScannerExtension` implements Burp's `BurpExtension`. It wires up `ExtensionConfigStore`, `ScanCheckSettings`, the `DiscoveryContentScanner`, `McpEventLog`, the `McpClientManager`, the `McpInsertionPointProvider`, the `ScanCheckRegistry` (with a lazily-created `CollaboratorClient` supplier and a `CurrentSelectionHolder` so the RCE / argument-traversal checks can scope to the table selection), the `McpScanLauncher`, the Swing UI tab (registered on the EDT), and the local `SseProxyServer` + `McpHttpHandler`. `CurrentAuthHolder` snapshots the active auth strategy so checks see a consistent view across a scan; both holders are cleared on disconnect.

**Key packages:**

- `mcp` — Protocol-level domain types: `McpRequestDetector` (classifies HTTP traffic as MCP via JSON-RPC) and `McpRequestKind` (`TOOLS_CALL`/`TOOLS_LIST`/`RESOURCES_READ`/`PROMPTS_GET`/`OTHER_MCP`/`NOT_MCP`). Also holds `BoundedBodyReader` — the shared UTF-8 body reader with an 8 MiB cap (`MAX_RESPONSE_BYTES`) that every untrusted-server response read goes through (`client/McpScannerSession` initialize body, `proxy/SseScanSession` auth-challenge body, `proxy/SseProxyServer` upstream body) so a hostile server cannot OOM Burp via an oversized response. Lives outside `checks/` and `scan/` so both can depend on it without cycles.
- `config` — `ExtensionConfigStore` is the persistence layer for all user settings (endpoint, transport, OAuth issuer/client/scopes, per-check enabled flags). Sits below UI and checks so both can read/write settings.
- `logging` — `McpEventLog` is the in-process event log surfaced by the Logger sub-tab and consumed by `client/`, `proxy/`, `ui/` for connection/audit/redirect/auth lifecycle events. Sits below those packages so they can write without depending on UI.
- `client` — `McpClientManager` is a thin coordinator that delegates to two collaborators per connection: `McpDiscoveryClient` (owns the langchain4j `McpClient` for tool/resource/prompt discovery) and `McpScannerSession` (owns the raw HTTP session used by scanning). `McpServerConfig` (record) holds endpoint + transport + auth. `TransportType` enum with SSE inference from URLs.
- `proxy` — Local NanoHTTPD-fronted proxy (`SseProxyServer` + `McpHttpHandler` + `JsonRpcIdRewriter` + `SseScanSession` + `ProxyResponse`) that intermediates scanner-issued requests. **Mandatory for SSE**: Burp's scanner cannot consume open-ended `text/event-stream` bodies, so the proxy terminates the stream locally, lifts the JSON-RPC reply out of the `event: message` payload, and hands Burp a bounded HTTP response. `JsonRpcIdRewriter` makes IDs unique per concurrent scan request. Do not attempt to replace this with synchronous intercept-and-respond inside `HttpHandler` (e.g. `RequestToBeSentAction.continueWith(...)` with a synthesised response) — the handler hook fires too late in Burp's scanner pipeline; the request goes out on the wire before the synthesised response is ready.
- `auth` — Strategy pattern: `AuthStrategy` interface with `headers()` plus optional `supportsRefresh()` / `refresh()` lifecycle hooks. Implementations: `NoAuthStrategy`, `BearerTokenAuthStrategy`, `CustomHeaderAuthStrategy`, and `OAuthAuthCodeStrategy` (OAuth 2.1 authorization-code-with-PKCE flow). The `auth/oauth/` subpackage holds the OAuth flow machinery (`OAuthAuthorizationFlow`, `OAuthSession`, `TokenRefresher`, browser/callback plumbing, `OAuthUrlValidator`). The `auth/oauth/discovery/` subpackage handles RFC 8414 / RFC 9728 authorization-server and protected-resource metadata discovery.
- `checks` — Eleven active scan checks: `McpActiveAuthBypassCheck`, `McpActiveHiddenMethodCheck`, `McpActiveResourcePathTraversalCheck`, `McpActiveOAuthTokenValidationCheck`, `McpActiveDnsRebindingCheck`, `McpActiveOAuthMetadataSsrfCheck`, `McpActiveDcrMisconfigurationCheck`, `McpActiveConsentPageReflectedXssCheck`, `McpActiveUnauthenticatedToolDiscoveryCheck`, `McpActiveToolArgumentPathTraversalCheck`, and `McpActiveToolArgumentRceCheck` (Collaborator-backed — gracefully degrades when Collaborator is unavailable in the running Burp edition). Many share a probe/runner split (`AuthProbe`/`AuthProbeRunner`, `JsonRpcMethodProbe`/`JsonRpcMethodProbeRunner`, `ResourcesReadProbeRunner`, `ToolsCallRceProbeRunner`, `ToolsCallTraversalProbeRunner`, `AuthorizeProbeRunner`) so payload generation and HTTP-execution-with-success-oracle are reusable across checks. The two path-traversal checks (`McpActiveResourcePathTraversalCheck` over `resources/read` URIs, `McpActiveToolArgumentPathTraversalCheck` over `tools/call` argument values) share a confidence-tiered model via `PathTraversalTier` {`ABSOLUTE`, `TRAVERSAL`, `ENCODING_BYPASS`, `PREFIX_SIBLING`} resolved by the shared `TraversalTierClassifier`: `ABSOLUTE` (bare absolute read, ambiguous → MEDIUM/TENTATIVE, hedged), `TRAVERSAL` (a `../` escape returning an out-of-root file matched by the corroborated `FileSignature` content oracle → HIGH/FIRM), `ENCODING_BYPASS` (literal `../` delivered-to-handler-and-rejected but an encoded twin succeeds → HIGH/CERTAIN, gated on positive delivered-and-rejected evidence so it never over-claims), and `PREFIX_SIBLING` (CVE-2025-53110 naive-`startsWith` containment, detected by the `FilesystemErrorOracle` not-found-vs-access-denied **error differential** + `AllowedRootDeriver` — a deny-control + non-existent prefix-sharing sibling, needing no planted secret → MEDIUM/FIRM). `FileSignature` also matches a newline-unescaped view so JSON-enveloped file leaks (`"content":"root:...\n..."`) are still detected. `FilesystemErrorOracle`/`AllowedRootDeriver`/`TraversalTierClassifier` are shared by both runners; symlink escapes (CVE-2025-53109) are out of scope (not remotely detectable). Plus two passive scan checks: `JsonRpcDiscoveryResponseScanner` (inspects `tools/list`/`resources/list`/`prompts/list`/`initialize` discovery metadata) and `JsonRpcResponseContentScanner` (inspects `tools/call`/`resources/read`/`prompts/get` runtime output) — both run the shared `ContentRuleEngine` over MCP-spec textual fields and share the `ContentRuleDescriptor.MASTER_ID` ("MCP Discovery Content Scanner") master toggle. `McpActiveConsentPageReflectedXssCheck` and `McpActiveDcrMisconfigurationCheck` run scan-start-only — once per scan via `ManagedScanStartCheck`, because they self-discover everything and would otherwise double-report across the scan-start and per-request surfaces — while `McpActiveOAuthTokenValidationCheck` runs on both surfaces (it needs the live bearer at scan-start, which the per-request baseline lacks). The `checks/registry/` subpackage wraps each check in `ManagedActiveCheck` / `ManagedPassiveCheck` / `ManagedScanStartCheck` so `ScanCheckSettings` (backed by `ExtensionConfigStore`) can toggle them on/off at runtime; `CheckDescriptor`, `ContentRuleDescriptor`, and `ScanCheckRegistry` enumerate them for the UI. The wrappers route every `doCheck` / `runOnceForSession` through `ScanCheckLogging`, which writes a single finish line (id + duration + issue count) to the `McpEventLog` on success and an error line on throw, then re-throws.
- `checks/content` — Sensitive-data scanner that runs on every Connect (not through Burp's scan pipeline). `DiscoveryContentScanner` walks the discovered `serverInfo`, tools, resources, resource templates, and prompts via `DiscoveryFieldWalker`, evaluates each `ContentRule` against the resulting `InspectedField`s, and emits `AuditIssue`s directly against the upstream host using the initialize handshake as evidence. `ContentRules.all()` returns the default catalogue from `checks/content/rules/`: regex-based credential detectors (`AwsAccessKeyRule`, `GithubPatRule`, `SlackTokenRule`, `StripeKeyRule`, `GoogleApiKeyRule`, `GcpServiceAccountRule`, `AzureConnectionStringRule`, `AiKeyRule`, `JwtRule`, `SshPrivateKeyRule`, `PgpPrivateKeyRule`, `CreditCardRule`, `EmailRule`, `PrivateIpRule`) plus `IconContentRule` for unsafe icon URLs. `ContentSuppression` does placeholder/example-field/entropy filtering (not dedup); `ContentFindingDedup` is the shared, thread-safe claim set keyed on `(ruleId, matchedValue, host)` that collapses duplicate findings across the connect-time `DiscoveryContentScanner` and the passive `JsonRpcDiscoveryResponseScanner` (which both run the same rules over the same connect-time discovery metadata) so a secret is reported once, not once per surface — `McpScannerExtension` injects one instance into both and clears it on disconnect. Gated by the master toggle in `ScanCheckSettings` under `ContentRuleDescriptor.MASTER_ID`.
- `scan` — `JsonRpcRequestBuilder` constructs `tools/call`, `prompts/get`, `resources/read`, and template-expanded `resources/read` requests with computed insertion point offsets. The three locator utilities (`ArgumentsObjectLocator`, `ArgumentValueLocator`, `UriValueLocator`) walk the request body via Jackson streaming to find fuzzable byte ranges. `UriTemplateExpansion` materialises RFC 6570 template variables into concrete URIs whose variable byte-ranges Burp can then fuzz. `McpInsertionPointProvider` dispatches on `McpRequestKind` to choose the right locator per request shape. `McpScanLauncher` kicks off audits against a `ScanInventory` (the aggregate of discovered tools, resources, resource templates, and prompts). `JsonSchemaDefaults` generates default argument values from JSON Schema.
- `ui` — Swing UI: `McpScannerTab` (main container, routes UI actions through a reducer), `ServerConfigPanel` (endpoint/transport/auth config), `ServerInfoPanel` (server-reported info/capabilities/instructions), `ScanChecksPanel` (per-check enabled toggles), `InspectorPanel`, and four inventory panels (`ToolTablePanel`, `ResourceTablePanel`, `ResourceTemplateTablePanel`, `PromptTablePanel`) sharing the `AbstractInventoryTablePanel` / `InventoryTableModel` base. The `ui/state/` subpackage owns the connection state machine: `UiConnectionState` (sealed type representing disconnected/connecting/connected/failed), `UiStateReducer` (pure transitions driven by `UiAction`s emitting `UiSideEffect`s), `ConnectAttempt`, and `ConnectionStatus` (toast-style messages). The `ui/widgets/` subpackage holds reusable widgets (`HeaderTablePanel`, `ScopeTablePanel`, `StatusCluster`, `HyperlinkLabel`, theme colors).

### Connection model

`McpClientManager` is a thin coordinator. The real work lives in its two collaborators:

- **`McpDiscoveryClient`** owns the langchain4j `McpClient` and exposes `discoverTools()`, `discoverResources()`, `discoverResourceTemplates()`, `discoverPrompts()`, and `fetchServerMetadata(...)`. The schema-to-Map translation for langchain4j's `JsonSchemaElement` hierarchy is inlined here as private helpers.
- **`McpScannerSession`** owns the raw HTTP session used by Burp scanning, including the transport-specific bring-up and auth-refresh-on-401 behaviour:
  - **Streamable HTTP** — sends a JSON-RPC `initialize` + `notifications/initialized` handshake to obtain an `Mcp-Session-Id` header, which is attached to all subsequent scan requests. `refreshScannerSession()` re-handshakes after a 401.
  - **SSE** — opens the SSE stream via `SseEndpointDiscoverer`, reads the first `event: endpoint` to discover the message URL (falls back to `/message`). No session header needed.

The `scannerHeaders()` map and `resolvedEndpoint()` accessors live on `McpScannerSession` — `McpScanLauncher` and the UI consume them when building scan requests.

### Insertion point offset computation

The central design challenge: Burp needs exact byte offsets into HTTP requests to know which ranges are fuzzable. Both `JsonRpcRequestBuilder` (for launching scans) and `McpInsertionPointProvider` (for Burp's built-in scanner) compute these by walking the request body with Jackson's streaming parser and tracking byte positions:

1. `McpInsertionPointProvider` dispatches on `McpRequestKind` to pick the right locator.
2. **Tools/prompts** — `ArgumentsObjectLocator` finds the `params.arguments` (or `params.arguments` for prompts) object's byte range; `ArgumentValueLocator` then yields a `ValueByteRange` per scalar argument inside it. Container values (objects, arrays) are skipped.
3. **Resources** — `UriValueLocator` finds the `params.uri` string's byte range.
4. **Resource templates** — `UriTemplateExpansion` materialises RFC 6570 variables into a concrete URI before locating the per-variable byte ranges within it.
5. For string values the offsets exclude the surrounding quotes so Burp fuzzes the content, not the delimiters. Offsets are then converted to absolute byte offsets (accounting for HTTP headers in `JsonRpcRequestBuilder`, or `bodyOffset()` in `McpInsertionPointProvider`).

### Schema bridge

langchain4j's `JsonSchemaElement` type hierarchy (`JsonObjectSchema`, `JsonStringSchema`, etc.) doesn't serialize directly to standard JSON Schema, so `McpDiscoveryClient` translates it to plain `Map<String, Object>` (private static helpers) before handing it to Jackson. Kept inlined because it's only used at discovery time and only by this one class.

## Key Libraries

- **Burp Montoya API** (`compileOnly`) — Extension interface
- **langchain4j-mcp** — MCP client/transport implementation
- **Jackson** — JSON serialization; `McpObjectMapper` provides a shared configured instance
- **NanoHTTPD** — Backs the local SSE proxy. Kept in place rather than swapped out even when audits flag CVE-2022-21230; mitigations live in `proxy/` rather than via library replacement.
- **Nimbus OAuth 2.0 SDK** — OAuth 2.1 / PKCE / DCR plumbing under `auth/oauth/`.

## Testing

JUnit 5 + Mockito + AssertJ + ArchUnit. `MontoyaTestFactory.install()` must be called in `@BeforeEach` — it installs mock stubs into Montoya's global `ObjectFactoryLocator` so static factory methods (`AuditResult.auditResult()`, `HttpService.httpService()`, etc.) work in tests. ArchUnit guards (e.g. `DeletedTypesTest`) lock in architectural invariants that previous refactors revealed — when one fails, treat it as a regression signal, not a test to delete.

A deliberately-vulnerable Python MCP test target lives under `test-server/` (uv-managed, Python 3.11+, Streamable HTTP). Use it to exercise checks end-to-end against realistic broken-but-configured failure modes — fixtures must simulate a *real* bug, not just a permissive config, or the check is a false positive.
