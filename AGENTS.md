# AGENTS.md

A Burp Suite extension that security-tests MCP (Model Context Protocol) servers: it discovers tools, resources, templates and prompts, builds JSON-RPC requests with insertion points and scans them with its own checks (optionally alongside Burp's). **Burp Suite Professional only** (Collaborator is needed for the out-of-band checks).

Architecture overview: [ARCHITECTURE.md](./ARCHITECTURE.md). Java 17.

## Commands

```bash
./gradlew build                                   # compile + unit tests + ArchUnit guards + request budgets
./gradlew test --tests McpRequestDetectorTest     # one test class
./gradlew shadowJar                               # fat JAR Burp loads: build/libs/mcp-server-scanner-extension-<version>-all.jar
./gradlew harnessJar                              # the same JAR plus the test automation (-harness.jar), loaded by cveTargetsBurp and burpCanary
./gradlew dependencies --write-locks              # after changing a dependency (gradle.lockfile mismatch)
./gradlew cveTargets [-Pcheck=<id>] [-Ptarget=<id>] [-Psmoke]   # CVE harness, needs Docker, not part of build
./gradlew cveTargetsBurp [-PburpConfig=extensions-only|with-builtins]  # same arms through headless Burp Pro
./gradlew cveTargetsLifecycle                     # harness self-test
./gradlew burpCanary                              # Burp send-latency canary (Burp Pro jar via -PburpJar or BURP_JAR)
./gradlew slowLinkTest                            # 100 ms-per-hop latency test; run `uv sync` in test-server/ once first
```

- **Always run `./gradlew shadowJar` after a code change**: the fat JAR is what gets loaded into Burp.
- Commit `gradle.lockfile` whenever you regenerate it.
- `build` does not run the latency or CVE suites (localhost hides serialised sends and locks held across a send): run `slowLinkTest` after changing send paths, locking or concurrency, `burpCanary` after changing connection reuse, and `cveTargets -Pcheck=<id>` after changing a check.
- Raise a declared concurrency in `SlowLinkIT` only when the code really sends that many requests at once, never to make it pass.

## Adding a check

Every check is exactly one of three kinds: `INSERTION_POINT` (once per fuzzed field), `REQUEST` (once per scanned request) or `HOST` (once per host trial, retried until conclusive by `HostAudits`). To add one, change no shared code:

1. Create `src/main/java/com/mcpscanner/checks/catalog/<check>/` with the check, a `<Check>Descriptor` constant, a `<Check>Issues` class and a `CheckFactory` that builds it from `CheckServices`.
2. Add the factory's class name as one line in `src/main/resources/META-INF/services/com.mcpscanner.checks.api.CheckFactory` (test-only `fixture*` checks register in the same file under `src/test/resources`).

Rules a check must follow (most are enforced by tests):

- A catalog check never depends on another catalog check, and shared code never names one (`CatalogIsolationTest`). A check may use only `checks/api`, `checks/issue`, `checks/shared/**`, `mcp`, `logging`, the `core/` libraries, Montoya, Jackson and the JDK.
- No passive checks (`CheckDisciplineTest`). Retired checks stay retired (`DeletedTypesTest`).
- Every invocation that does not run, or stops early, logs why through `CheckLog.notRun` (`SkipLoggingGuardTest`). HOST checks never log or dedup their own claims; `HostAudits` does.
- A check reading the reply overrides `requiresReply()` so notifications are skipped for it.
- No check thread waits on Collaborator: register payloads with `CollaboratorWatch` and report through `CheckServices.lateIssues()`.
- Open probe sessions only through `checks/shared/session`; never DELETE or disturb the scanner's live session.
- When Burp refuses a `text/event-stream` reply, recover with `StreamingFallback` and report what went outside Burp through `OutsideBurpSends`.
- OAuth checks send through `checks/shared/oauth/OAuthHttp`, revoke every token they obtain and delete every client they register. Pass evidence that may hold secrets through `checks/shared/redaction/ExchangeRedactor`.
- If a change legitimately alters how many requests an operation sends, update its row in `performance/RequestBudgets` in the same change and say why.

## Traps

- **Do not replace the local proxy with a synchronous intercept in `HttpHandler`** (`RequestToBeSentAction.continueWith(...)` with a synthesised response). The hook fires too late in Burp's scanner pipeline and the request is already on the wire. The proxy is mandatory for SSE. The one exception is `Http1LoopbackRelay`, which uses `RequestToBeSentAction.spoof`.
- **Never read Burp's site map or `Audit.issues()` on the EDT**: it can deadlock Burp. Go through `ui/widgets/UiReads` / `OffEdtFeed`.
- Burp refuses streamed (`text/event-stream`) replies to extensions. Recognise that only through `mcp/BurpStreamingRefusal`, never by Burp's obfuscated exception class names, which change between releases.
- Read every untrusted response body through `mcp/BoundedBodyReader` (size cap).
- Build URL requests only with `http/BareRequests.fromUrl` (`CodeHygieneTest`): Montoya's `httpRequestFromUrl` starts from Burp's browser template and would send its headers to the target.
- Scanner sentinel headers (`X-Mcp-Scanner-*`, `ScannerSentinels`) route requests through the proxy and must never reach the target; anything forwarded upstream goes through sentinel stripping, or `McpHttpHandler` loops it back to the proxy.
- Never resend a request that may write. Stale-connection resends are limited to reads and handshakes (`mcp/ResendableRequests`).
- Never send a `tools/call` to a tool that may write without the user's confirmation: decide read-only only through `mcp/ToolSafety`, and confirm writes through `ui/DestructiveScanGate` (or `ui/MiningWriteConfirmation` when collecting IDs).
- Never persist a credential (token, secret, credential header value): settings and the identities document are saved without secrets, which live in memory only.
- MCP framing, negotiation and SSE semantics live only in the core libraries (`core/`, packages `com.mcpscanner.core.protocol`, `.oauth` and `.connection`). Do not reimplement them in the extension.
- Persisted setting keys keep old names (`mcp.mining.*`, `connectAs`, provenance `MINED`) so saved projects load; do not rename them. User-facing text says "Collect IDs" / "collected", never "mine".
- NanoHTTPD stays despite CVE-2022-21230 audit flags; mitigations live in `proxy/`.
- `engine` and `http` are low-level packages with strict allowed dependencies (`LayeringTest`, `CycleFreedomTest`).

## Testing

- JUnit 5, Mockito, AssertJ, ArchUnit. Call `MontoyaTestFactory.install()` in `@BeforeEach` so Montoya's static factories work outside Burp.
- An ArchUnit guard failure (`src/test/java/com/mcpscanner/architecture/`, `DeletedTypesTest` and friends) is a regression signal. Fix the code; do not delete or loosen the test.
- Fixtures and test servers must simulate a *real* bug, not just a permissive configuration, or the check under test is a false positive.
- `test-server/` is a deliberately vulnerable Python MCP server (uv, Python 3.11+, Streamable HTTP, optional TLS and mTLS).
- `CheckRunner` runs any catalog check against a live target without Burp (see ARCHITECTURE.md).

### CVE target harness

`cve-targets/<check-id>/<target-id>/` holds real vulnerable/fixed Docker pairs, each with a `compose.yaml` and a `target.json` manifest; the harness asserts each arm's declared fire/silent outcome and always tears it down. Full reference: [cve-targets/README.md](./cve-targets/README.md).

- Compose files must join the external `mcp-cve-targets` network and never create their own.
- Name helper services per target: the harness refuses to start an arm while another project on the network uses one of its helper service names.
- `-Psmoke` keeps only targets marked `"smoke": true` (one fast real pair per check).
- A `silent` arm fails unless at least one check probe reached the target, except for a declared `knownMiss`.

## Package map (`src/main/java/com/mcpscanner/`)

- `McpScannerExtension`, `*Wiring`, `ExtensionFoundation` — entry point and object graph.
- `mcp` — protocol-level domain types shared by checks and scanning (request detection, bounded reads, SSE parsing, tool safety).
- `config` — persisted settings.
- `logging` — the in-process event log shown in the Logger tab.
- `http` — Burp HTTP plumbing leaf: request building, connection reuse, request counting, upstream evidence; `http/wire` is a raw-socket HTTP/1.1 sender.
- `client` — connecting to an MCP server: discovery, the scanner session, Burp and JDK transports, redirects, stale-connection resends.
- `proxy` — local loopback proxy that sits between Burp's scanner and the target (SSE unwrapping, JSON-RPC id rewriting, credentials, evidence capture).
- `auth` — authentication strategies; `auth/oauth` OAuth 2.1 with PKCE, DCR and metadata discovery.
- `identity` — users (primary and compared), their credentials and owned values.
- `access` — Check access (cross-identity comparison) and `access/mining` (collecting IDs).
- `checks` — `api` (kernel and kinds), `registry` (Montoya adapters), `issue` (issue rendering), `shared` (toolkits), `catalog/<check>` (one package per check).
- `scan` — request generator (`scan/request`), field and insertion-point generator (`scan/field`), launcher and scan modes.
- `engine` — the extension's own scan engine (extension checks without Burp's built-in ones).
- `automation` (in `src/automation/java`, not `src/main`) — loopback-only test automation API used by the headless Burp harness. It ships only in the harness JAR (`./gradlew harnessJar`), found through `ExtensionAutomation` and `META-INF/services`; `check` fails if it reaches the release JAR.
- `ui` — Swing UI; `ui/state` holds the connection state machine.
