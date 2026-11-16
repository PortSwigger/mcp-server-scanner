# Architecture

How the extension fits together. For build commands and the rules agents must follow, see [AGENTS.md](./AGENTS.md). Class-level behaviour is documented by the code and its tests; this file covers the shape and the reasons behind it.

## Wiring

`McpScannerExtension` (Burp's `BurpExtension`) builds the object graph through the `*Wiring` classes and `ExtensionFoundation`: settings, the event log, the client manager, the check registry, the scan launcher, the local proxy and the Swing tab. `ConnectionWiring` builds **one** upstream transport (`SharedUpstreamTransport`) that Connect, discovery and the proxy all share, and `ShutdownHooks` closes executors and pollers on unload.

## Connecting to a server

`McpClientManager` coordinates `McpDiscoveryClient` (catalog listing and mapping) and `McpScannerSession` (protocol bring-up and the live session scanning uses). Three transports:

- **Modern HTTP**: `server/discover`, versioned request metadata and routing headers, no session id.
- **Initialize-based Streamable HTTP**: `initialize` + `notifications/initialized`, version negotiation, `Mcp-Session-Id`.
- **Legacy SSE**: open the event stream, read the `endpoint` event for the message URL.

**Networking.** HTTP traffic goes through Burp's own HTTP stack while "Send requests through Burp" is on (the default), so Burp's client TLS certificates, upstream proxy and TLS settings apply; otherwise it goes through the JDK client. SSE always uses the JDK client, because Burp cannot read an open event stream. Burp also refuses `text/event-stream` replies to extensions; the Burp transport detects that (`mcp/BurpStreamingRefusal`) and either falls back to the JDK client for that route or offers to turn the setting off. Burp reports every streamed reply as a refusal (first, repeated, concurrent or on a reused connection) and returns an empty reply only when the server sent nothing before closing, so an empty reply is never taken for a stream and a call that may write is never resent after one. A check's `StreamingFallback` covers probes that do not go through the proxy and tells `StreamingRefusalWatch` (`OutsideBurpSends.streamRefused`) when Burp refused one; a check opening its own stream outside Burp is not a refusal.

**Connection reuse.** Burp keeps an extension's HTTP/1 connection alive only when a send names a connection id, and otherwise waits for the server to close after each reply. `ConnectionReusingHttp` names one for origins known to speak HTTP/1.x. A kept-alive connection the server closed before replying is resent once on a fresh connection, but only for reads and handshakes (`mcp/ResendableRequests`), never writes.

The MCP protocol, OAuth and connection-core logic (framing, negotiation, response validation, SSE semantics) lives in the project's own core libraries, Java 17 Gradle subprojects in `core/` with no third-party dependencies: `mcp-protocol-core`, `mcp-oauth-core` and `mcp-connection-core` (which depends on the other two), in the packages `com.mcpscanner.core.protocol`, `com.mcpscanner.core.oauth` and `com.mcpscanner.core.connection`. `core/core-module.gradle` builds each as a reproducible JAR plus sources JAR (other projects consume these) and runs every test-source class with a `main` method as a self-checking test (`selfTest_*` tasks, wired into `test`). They are the only implementation of it: generated scan requests are framed through `McpScannerSession.operation`, and catalog checks may call the protocol core directly.

## The local proxy

`proxy/SseProxyServer` is a loopback NanoHTTPD server that sits between Burp's scanner and the target. `McpHttpHandler` swaps the service of every scanner request so it reaches the proxy, which then:

- terminates SSE streams and hands Burp a bounded HTTP response (Burp's scanner cannot consume an open event stream, so the proxy is mandatory for SSE);
- rewrites JSON-RPC ids so concurrent scan requests stay distinct, and restores the scanner's id on the reply;
- injects the primary user's credentials and live `Mcp-Session-Id`, re-handshaking on session-not-found (but forwards a fuzzed, unknown session id unchanged);
- re-frames every forwarded body (routing headers and `Mcp-Param-*` headers derived from the body), so a check that swaps a body only needs `withBody`;
- relays upstream status and headers faithfully, and relays HTTP errors on handshakes instead of turning them into 502s;
- forwards a scanned `initialize` (Burp's or a check's fuzzed copy of the generated one) in a session or SSE stream of its own, never on the live session, because a server that accepts a second `initialize` resets the session and every later request on it fails (`HttpForwarding`, `IsolatedHttpForwarder.forwardInitialize`, `SseForwarding`).

Scanner-internal **sentinel headers** (`ScannerSentinels`, `X-Mcp-Scanner-*`) steer routing: direct delivery (bypass the proxy), strip credentials, run as another identity, keep the live session. They are stripped before anything goes upstream. The proxy refuses browser-originated requests (`Origin` / `Sec-Fetch-*`) that do not carry its per-load routing key, so a DNS-rebinding page cannot use the loopback port.

**Why not intercept in `HttpHandler`?** Synthesising a response with `RequestToBeSentAction.continueWith(...)` fires too late in Burp's scanner pipeline; the request is already on the wire. The only exception is `Http1LoopbackRelay`, which uses `spoof` for HTTP/2 and non-Scanner requests because Burp fixes the HTTP mode before the handler runs.

**Issue evidence shows the target's exchange, not the proxy hop.** Each forward records what was actually sent upstream (`UpstreamCaptures`, `RecordingTransport`) into a bounded `UpstreamExchangeStore`, and tags the reply with `X-Mcp-Scanner-Exchange`. `http/UpstreamEvidence` swaps tagged proxy exchanges in an issue for the stored upstream ones, carrying highlight markers over by text.

## Checks

Every check is one of three kinds, decided by its interface:

| Kind | Interface | Called |
|---|---|---|
| `INSERTION_POINT` | `InsertionPointCheck` | once per fuzzed field |
| `REQUEST` | `RequestCheck` | once per scanned request |
| `HOST` | `HostCheck` / `RetryingHostCheck` | once per host trial per connection, until a trial settles |

HOST checks register with Burp as per-request: Burp's own per-host invocation would stop retries, so `HostAudits` is the only host dedup. A trial settles, is released unprobed, or is released as inconclusive or as an unsuitable seed, each with a retry limit.

Packages under `checks/`:

- `api` — the kernel: descriptors, kinds, `CheckFactory` (the `ServiceLoader` SPI), `CheckServices`, `CheckCatalog`, `CheckRunner`, `HostAudits`, `CheckLog`. `api/crossidentity` is the probe kit shared by Check access and session binding.
- `registry` — the Montoya side: `McpCheckAdapter` and one adapter per kind, owning toggles, lifecycle logging and the evidence swap. It never names a concrete check.
- `issue` — issue rendering shared by checks.
- `shared` — toolkits: JSON-RPC parsing (`jsonrpc`), probe sessions (`session`), anonymous probing (`probe`, `auth`), event-stream probes (`stream`), Collaborator (`collaborator`), OAuth (`oauth`), field naming, redaction.
- `catalog/<check>` — one package per check.

**Streamed replies.** Burp discards a check invocation's whole result once any send met a streaming refusal, even one the check recovered from. The adapter detects this and files the issues itself. `StreamingFallback` recovers probes outside Burp (JDK client, or a raw socket for foreign `Host` headers), and every such send is reported through `http/OutsideBurpSends` so request counts stay right.

**Collaborator.** No check thread waits for interactions. `CollaboratorWatch` is one shared poller per load; a check registers its payloads and returns, and findings arrive later through `lateIssues()`, which routes them through the same adapter and site-map consolidation as returned issues.

**Rate limits.** Fuzzing checks stop probing after the first HTTP 429; every check's `Http` honours a short `Retry-After` once.

## Scan generation

- `scan/request` — the request generator: one builder per `RequestFamily` (tool calls, resource and template reads, prompts, list requests, notifications, lifecycle requests, OAuth client registration), filtered by the user's toggles, the server's capabilities and the negotiated version.
- `scan/field` — the field generator: every JSON leaf under `params` becomes an insertion point, plus non-transport request headers and resource-template variables. Burp builds with native JSON-RPC insertion points get those argument leaves left to Burp, so fields are not fuzzed twice.
- `McpScanLauncher` renders each request once and sends the batch to the chosen `ScanMode`: the extension's own engine (default) or a Burp audit with the built-in checks too.
- `OwnedArguments` fills a tool call's arguments from the primary user's owned values, so Scan and Check access send the same owner request.

## The extension's scan engine

Montoya cannot start an audit without Burp's built-in checks, so `engine/McpScanEngine` runs the same `McpCheckAdapter` instances itself on a resizable worker pool: per-insertion-point checks once per field, request and host checks once per request. Issues are consolidated against the live site map the way Burp does. Its probes appear in Burp as tool "Extensions". The Scans tab shows its history.

## Users and Check access

- `identity` — every user (one **primary user** that Connect and Scan run as, plus compared users), their in-memory credentials and owned values. Credentials are bound to the endpoint's origin and cleared when it changes.
- `access/mining` — "Collect IDs": calls read-only tools as each user to learn which object ids are theirs. Write tools run only when opted in and confirmed. Every user's calls in a pass run concurrently on as many workers as extension scans use (`mcp.scan.engine_workers`); each pass waits for the previous one because it feeds that pass's IDs. By default a user is sent whatever their passes need; `mcp.mining.requests_per_user` sets an optional ceiling.
- `access/comparison` — Check access: per item, the owner's request, a replay as each compared user and an anonymous replay, with escalation probes where they can matter. Operation-level findings are filed as Burp issues; object-level ones only when a hand-entered private marker proves them, otherwise they stay on the Access grid as possible leaks.

## Running checks outside Burp

`CheckRunner` mirrors Burp's dispatch so a check can run against a live target without Burp:

```java
MontoyaTestFactory.install();
Http http = new RecordingRealHttp();
McpCheck check = CheckCatalog.discover(services).find("<check-id>").orElseThrow();
List<AuditIssue> issues = new CheckRunner(http, new McpInsertionPointProvider()::provideInsertionPoints)
        .run(check, baseRequests);
```

`CheckServices.standalone()` supplies no-auth, no-Collaborator defaults. A check that reports through Collaborator needs `services.reportingLateIssues(watch, new SettlingLateIssues(watch))` and a `CheckRunner` given that settlement.

## Test infrastructure

- **Request budgets** (`performance/RequestBudgets`, part of `build`): Connect, every catalog check and a Check access item each have a request budget against in-process fixtures; exceeding one fails with a breakdown.
- **CVE target harness** (`cve-targets/`, `src/test/java/com/mcpscanner/cvetargets`): real vulnerable/fixed Docker pairs, run directly through `CheckRunner` or through headless Burp Pro using the loopback-only `automation` API (`/scan-all`, `/audit`, `/check-access`), which lives in `src/automation/java` and ships only in the harness JAR. See [cve-targets/README.md](./cve-targets/README.md).
- **Burp canary** (`burpCanary`): headless Burp against a local keep-alive server, failing if connection reuse is bypassed or sends serialise.
- **Slow link** (`slowLinkTest`): runs Connect, Check access and a scan through a relay that adds latency per hop, failing any operation slower than its request count and declared concurrency allow, or any traffic that bypassed the relay.
- **mTLS**: `MutualTlsConnectTest` in Java; `test-server/` serves HTTPS with client certificates for a manual Burp check.
