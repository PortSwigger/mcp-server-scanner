# MCP Server Scanner Extension

A Burp Suite extension for security-testing [Model Context Protocol](https://modelcontextprotocol.io) servers.

Discovers MCP tools, resources, resource templates, and prompts, builds JSON-RPC 2.0 requests with fuzzable insertion points, and runs its own MCP checks against them, on the extension's own scan engine or in a Burp audit alongside Burp Scanner's built-in active checks.

## Burp editions

- **Burp Suite Community:** connect (including OAuth sign-in), browse tools, resources, templates and prompts, ask the server for values, and send requests to Repeater and Organizer. Scanning, Check access and Collect IDs are not available.
- **Burp Suite Professional:** everything, including scanning, Check access and Collect IDs. The out-of-band checks also need Burp Collaborator.

## Features

- **Protocol and transports:** Auto detects modern `server/discover` HTTP, initialize-based Streamable HTTP, then legacy SSE. Explicit modes are available. A local proxy lets Burp's scanner consume `text/event-stream` replies.
- **Auth:** each user has its own credentials: none, a bearer token, custom headers, or an OAuth 2.1 sign-in with PKCE. All OAuth users sign in through one shared OAuth client. It supports pre-registered clients, hosted Client ID Metadata Documents, and legacy dynamic client registration, with protected-resource and OAuth/OIDC authorization-server discovery.
- **Access control between users:** scan as one user and compare what other users, a caller with no credential and a caller with a fake token can list, call and read.
- **Active checks:** 17 scan checks, listed under [Checks](#checks).

Aimed at MCP server **operators** auditing their own deployments.

## Checks

Each check has a toggle in the **Checks** section. Severity is the headline rating; a check that reports several findings lists each one.

An issue attaches only the exchanges that prove it; other requests the check sent are named in the issue detail, not attached. Evidence is the raw exchange with the target (not the hop through the extension's local proxy), credentials included, so you can send it to Repeater as is. On legacy SSE, where the answer arrives on the event stream rather than in the POST's reply, each exchange is two items: the POST with the server's own reply (usually `202 Accepted`), then the `GET /sse` that opened the stream with the raw event that answered it.

| Check | Kind | Severity |
|---|---|---|
| MCP unauthenticated request execution | per request | High |
| MCP session binding across identities | per request (one probe per host and compared user) | High / Firm when another user's credential reads the owner's result on the owner's session and the owner's private marker confirms it; Medium / Tentative without the marker; Medium when another credential rebinds a session |
| MCP Origin/Host admission | per host (retried until conclusive) | Medium; High when CORS lets a foreign origin read the replies without credentials (or with cookies the server approves for it), Low with header credentials |
| **MCP cross-client response leak** | per host (retried until conclusive) | High / Firm when concurrent clients sending the same JSON-RPC id receive each other's echoed tool results in every same-id round, and every distinct-id round stays clean |
| MCP command injection (Collaborator-backed) | per field | High; Medium / Tentative for argument injection, when a value is parsed as a command-line option |
| MCP file path traversal | per field | High |
| **MCP SQL injection** | per field (and each host or path segment of a URI value) | High / Firm when SQL-only syntax (a `--` line comment or backtick identifier quoting) and a second, independent syntax family each reproduce the baseline reply while a same-characters falsifier changes it, confirmed over three rounds; High / Tentative with one family. A field that runs whole SQL statements by design (a SQL console tool) is not reported |
| MCP outbound request (Collaborator-backed, including payloads after a URL value's own host to pass prefix allowlists, and OAuth registration URL fields) | per field | Medium |
| **MCP SSRF address filter bypass** (Collaborator-backed) | per field (URL argument of fetch, browse and scrape tools) | High / Firm when the reply to the loopback spelling contains the target's own page; High / Tentative when the spelling is only no longer refused and the same spelling of the Collaborator address is fetched |
| MCP downstream route escape | per field | Information |
| MCP JWT access token validation | per host | High |
| MCP OAuth refresh grant validation | per host | Medium |
| MCP OAuth redirect policy | per host | Medium / Firm when an authorization code reaches an unregistered redirect URI; Information for error redirects, script-scheme registration, wildcard expansion, and anonymous dynamic client registration that accepts an HTTPS redirect URI on an unrelated host ("OAuth dynamic client registration accepts redirect URI on any host") |
| MCP OAuth consent page HTML structure reflection | per host | Information |
| **MCP OAuth authorization without login or consent** | per host | High / Certain when the code redeems to a token that opens a refused request; Medium / Firm when a code is issued with no login or consent page; Medium / Tentative when the server first created an anonymous session; Information when the endpoint already answers without a token. With the opt-in signed-in trial (see [Testing OAuth consent with your sign-in](#testing-oauth-consent-with-your-sign-in-professional)): High when consent is skipped for a signed-in user or remembered by client name, redirect host or `client_id` prefix; Medium when consent is not asked again for a broader scope |
| **MCP OAuth authorization code redeemed more than once** (part of the check above) | per host | Medium / Certain when a second sequential or concurrent redemption returns a working token |
| **MCP sibling route authentication parity** | per host | Low / Firm when the main route refuses a catalog listing without credentials and a sibling route (`/mcp_message`, `/messages`, `/message`, `/sse`, `/mcp/` and similar) or the advertised legacy SSE message route answers it |
| **MCP session lifecycle** | per host | High / Firm when probe session IDs are guessable (repeated, increasing, known time-based formats — UUID v1/v6/v7, ULID, KSUID, Snowflake, ObjectId — whose clock and counter fields leave under 64 random bits, or under 64 varying bits after hex/base64 decoding; up to 30 probe sessions when the first eight are borderline) and a bare ID runs a request without credentials; Low / Firm for guessable IDs alone (Tentative when only the live session's ID repeats); Low / Firm when a session still answers ping, or still opens its GET event stream (while a never-issued ID's stream is refused), after a successful DELETE. Runs only when the server issues `Mcp-Session-Id`, or on legacy SSE (guessability only, on probe streams of its own, skipped when the message route carries no session id); uses its own probe sessions and never touches the scanner's |

### Requests sent by Scan

The **Requests** section picks which request families Scan builds and two insertion-point options:

- **Offer MCP headers as insertion points**: fuzz `Mcp-Method`, `Mcp-Name`, `MCP-Protocol-Version` and `Mcp-Session-Id`.
- **Fuzz request metadata (_meta) on every request**: off by default. The `params._meta` envelope is handled by the same server code on every request, so by default a scan fuzzes it once per server, on one base request (a listing or lifecycle request when the scan has one), and leaves it alone on the rest. Turn it on to fuzz `_meta` on every request.

## Build

```bash
./gradlew shadowJar
```

Output: `build/libs/mcp-server-scanner-extension-2.2.0-all.jar`.

Requires Java 17.

## Install

In Burp: **Extensions → Installed → Add → Java**, then select the fat JAR above.

Open the **MCP Server Scanner** tab, enter the server endpoint, and connect. Connect, discovery and Scan run as the **primary user**, shown next to the Connect button as **as [User 1 · Detect automatically ▾]**. A new project's User 1 is set to **Detect automatically**: Connect tries without credentials, signs in with OAuth if the server advertises it, and if the server refuses, a strip under the endpoint asks for a bearer token right there and reconnects with it. Credentials are per user and live in the **Users** tab.
Leave **Transport** on **Auto** unless you need to force a specific protocol family. The descriptions beneath the controls explain the supported versions and authentication choices. Protocol dates are negotiated automatically. After connecting, **Server Info → Connection** shows the selected mode, actual transport and protocol version, effective endpoint, and authentication mode, even after scan status changes. Existing saved Streamable HTTP and SSE choices still load.

For OAuth, the **OAuth client** section of the **Client** tab is shared by every user who signs in with OAuth. The issuer is discovered from the MCP server unless you enter one. Choose **Auto** registration when the server advertises a usable method. Use **Pre-registered** when you have a client ID from the authorization server, or **Client ID Metadata Document** when you host a public HTTPS client metadata document. Use **Dynamic registration** only with servers that still expose a registration endpoint. The OAuth callback uses a loopback address; set a fixed callback port when the server requires an exact registered redirect URI. The **Scopes** table lists the scopes the server advertises and any you add: Connect requests the advertised scopes you leave ticked plus the custom scopes you tick, and nothing when nothing is ticked. The OAuth client is locked while connected. The rest of the Client tab sets how the extension presents itself in the MCP handshake and in dynamic registration; its **Software ID** defaults to the extension's own fixed `software_id`, the same in every install and version. For a machine-to-machine server, set the primary user's auth to **OAuth client credentials** (or **OAuth enterprise-managed**, when an identity provider plugin is installed) and fill in its grant settings in the Users tab.

**Settings follow the Burp project.** To start every new project (including temporary ones) with your own choices, click **Save as my defaults** in the extension's **Settings** (also under Burp **Settings > Extensions**). It saves how you work: redirects, limits, workers, networking, server pings, Send to handling, scan mode, checks and request families, header and `_meta` fuzzing, OAuth redirect port, Collect IDs passes and the client identity (except its version). These live in Burp's user preferences. A new project takes your defaults once, when it is first opened; projects you already have keep their own settings. The server, users, credentials, OAuth registration mode and client details, tool choices, "Don't ask again", write-tool opt-ins and the **Always (risky)** redirect mode stay in the project only. **Reset my defaults** sends new projects back to the built-in defaults and leaves the current project as it is.

### Testing OAuth consent with your sign-in (Professional)

The OAuth consent check can also test whether the authorization server skips or wrongly remembers consent for a user who is already signed in: consent granted to any client, consent remembered by client name, redirect host or client ID prefix, or consent not asked again for a broader scope. This acts on your account, so it is off by default. Turn it on per project with **Test OAuth consent with my sign-in** under the Checks section; the choice is saved in the project, never in your user settings, and Burp Suite Community does not show it.

The check uses one of two signed-in sessions:

- **Burp's cookies for the authorization server**: cookies in Burp's cookie jar (Settings → Sessions) for the authorization server's host, used when at least one covers the authorization endpoint's path; each request on the way to the consent page carries only the cookies whose path covers it. Burp does not say whether a cookie was host-only and stores `Domain=example.com` and a host-only `example.com` cookie alike, so a parent-domain cookie such as `example.com` is sent to `auth.example.com` only when the `Set-Cookie` that set its current value, found in Burp's Proxy history, had a `Domain` attribute; if Proxy history no longer holds it, the cookie is not sent. Sign in to the authorization server through Burp's browser first. Cookie values are sent only to that server and are never logged or saved; issue evidence shows the raw requests, cookies included.
- **Your browser right after an OAuth sign-in at Connect**: when Connect signs in with OAuth, the check learns the scanner's client (name, client ID, redirect URI, granted scopes) and right after sign-in opens one probe authorization (a probe client with the name the server registered for the scanner's client, and a redirect URI on another loopback host than Connect's) in the same browser, listens 10 seconds for a code but counts it only if it arrived within 2 seconds (a later code could be an Approve click, so it is logged and not reported), never redeems it, and deletes the probe client. Only when that code arrived without asking does it open a second one with a new client name. A pre-registered client's registered name is unknown, so the check goes straight to the new-name probe. What it saw is forgotten on Disconnect.

With Burp's cookies the check runs five probes, each with a probe client of its own: a fresh client name, the name the server registered for the scanner's client (skipped for a pre-registered client or without an OAuth sign-in at Connect, as its registered name is unknown), its redirect host, its `client_id` prefix, and a scope broader than the one you approved. It reports only the most specific shortcut: **MCP OAuth consent skipped for signed-in user**, **remembered by client name**, **remembered by redirect host** or **remembered by client_id prefix** (High), or **not re-asked for broader scope** (Medium). A code seen by the browser probe after Connect is reported the same way as Tentative.

What it does to your account: it registers probe OAuth clients and deletes them afterwards, and when the server hands a probe client a code without asking, it redeems that code once for a token in your name to prove the access, then revokes the token. On a safe server one extra consent tab may appear in your browser after Connect: close it, do not approve it.

Use **Send to Repeater** on a discovered tool, resource, template, or prompt to edit and replay a request. The local proxy supplies the primary user's credentials and transport session headers when sending it upstream.

### Testing access control between users

The **Users** tab has the **Primary user** and the **Compared users**. Each compared user has a name, its access compared with the primary user (**Same (peer)**, **Less access** or **More access**) and its own credentials. Add one with **Add user ▾**: a bearer token, custom headers, an OAuth 2.1 sign-in, or no credentials. **Sign in all** signs in every OAuth user that needs it. Credentials stay in memory and are never saved to the project. Secret fields are masked; click the eye to show a value.

Pick the primary user from the menu beside Connect, or with **Make primary user** in a compared user's editor. While connected, changing it asks whether to reconnect. On **Reconnect**, running scans stop and the scanner session restarts as the new user. The previous primary user becomes a compared user. **Detect automatically** and the OAuth grant kinds belong to the primary user only.

Tick **Compare** for the users to compare with the primary user. Check access always also tries every item as two callers with no real credential: **No credential** (no credentials sent; it has its own row in the Users table) and **Fake token** (a made-up token the server never issued, sent as a bearer token or in the primary user's custom credential header, made up afresh for each Check access run and never saved). It runs with only the primary user configured.

Each user can also have an optional **Private marker:** text only that user should ever see. When it shows up in another user's result, that is evidence of a leak.

Each user also keeps **owned values**: argument names with that user's own ids, such as `documentId → 42`. Tools that take an object id need a real one. A made-up id fails for every user, so an access bug stays hidden. A value is either **entered** (typed in, or owned objects saved by an earlier version) or **collected** from the server's replies by **Collect IDs** in the Access tab, in which case it records the operation and field it came from and whether it is **private** to that user or **shared** with others. Owned values are saved in the Burp project, never with reply text or credentials, and collected ones can be removed with "Clear collected IDs…" for one user or all. For each argument a tool call uses the user's first entered value, else its first private collected value; shared values are never used as owned ids.

After Connect, each compared user lists the server's tools and resources in its own MCP session. The **Access** tab shows what each user lists. After **Check access**, it also shows what each can call. Set **Who should reach it** per item, and mark items **Anyone — same result for everyone** to silence them.

Cross-user testing is **Check access**, not a scan check. Check access lists tools as No credential and as the Fake token too, so a tool only they can see still gets a row, then sends each item as its owner (with the owner's owned values in place of schema defaults, as Scan does), then as every compared user, with No credential and with the Fake token. The Access grid has a column for each, showing whether the item was listed and what the call returned. Write tools still need confirmation. It reports:

- a lower-privilege user reaching an operation its expectation forbids (also retried at older MCP protocol versions when refused), filed in Burp as High;
- one user's private marker in another user's result, filed as High / Firm;
- the owner's credentials reaching another user's object by that user's owned id (entered or collected): filed as High / Firm only when that user's private marker appears, otherwise shown on the Access grid as a possible finding.
- another user getting the owner's exact result for a call that carries one of the owner's own values, when the same call with an invented value of the same shape is refused: shown on the Access grid as a possible finding (Tentative); filed as High / Firm only when the owner's private marker appears;
- **MCP fake token lists tools the primary user does not list**: the server accepted a token it never issued and listed more than the primary user's real credential does (an unknown token mapped to a privileged default or service account), filed as High / Firm, or High / Certain when Check access then called one of those tools successfully with it;
- **MCP unauthenticated principal lists more tools than a real user**: No credential or the Fake token lists every tool a signed-in user lists plus more, filed as Medium / Firm, or High / Certain when one of the extra tools answered a call.

**Ratings:** collected IDs alone never file a Burp issue. A Firm object-level issue needs a private marker you entered; without one the Access grid shows a Tentative possible finding. Another credential running in a user's MCP session is the separate **session binding** scan check, listed in the Checks section.

It works on modern HTTP, initialize-based Streamable HTTP and legacy SSE. Burp scans of captured traffic (for example from Claude Desktop) no longer replay requests as other users.

Next to **Scan**, a chip reads **Scan as alice · compare bob ▾**. With nobody ticked, it reads **Scan as alice · no comparison ▾**. Its menu is a shortcut to the same choices as the Users tab: pick the primary user, and tick who to compare. Users without credentials are greyed out and marked "(needs credentials)".

If the primary user has no credentials and the server refuses its tool calls, the strip under the endpoint says how many calls were refused and offers **Add credentials for** that user, and the Users tab is marked **▲**. This happens when a server accepts the connection anonymously but refuses the real work.

After Connect, **Server Info → Overview** shows an **Authentication** block: who is connected, the method, issuer, client, scopes, token expiry with **Refresh**, and the masked access and refresh tokens with **Copy**.

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

See [`ARCHITECTURE.md`](./ARCHITECTURE.md) for the architecture overview and [`AGENTS.md`](./AGENTS.md) for contributor and coding-agent instructions.
The MCP protocol, OAuth and connection core libraries the extension is built on live in [`core/`](./core) as Gradle subprojects; `./gradlew test` runs their tests too. The `cve-targets/` directory holds deliberately vulnerable third-party servers used only to test the checks; it is never shipped in the extension JAR (see [`cve-targets/THIRD_PARTY.md`](./cve-targets/THIRD_PARTY.md)).

## Threat model and scope

Use this extension only on MCP servers you own or have written authorization to test.

Scans are intrusive: they send malformed JSON-RPC requests, fuzz tool arguments (which may invoke side-effectful tools on the target server), trigger Burp Collaborator out-of-band interactions, and may briefly stall the target server under load.

This tool is designed for MCP server **operators** auditing their own deployments. It is not designed for opportunistic scans against MCP servers you do not control.

## Known limitations

- **Scanning needs Burp Suite Professional**: see [Burp editions](#burp-editions).
- **Collaborator-backed checks**: within Professional, the command-injection check's out-of-band payloads, the outbound-request check and the SSRF address filter bypass check require Burp Collaborator. Without Collaborator they produce no out-of-band findings.
- **Requests outside Burp's networking**: with **Send requests through Burp** on (the default), the MCP connection's requests (including the event-stream request that checks whether an SSE server needs sign-in) go through Burp, so its upstream proxy, client TLS certificates and TLS settings apply; with it off, they go directly through Java's HTTP client. OAuth sign-in, Check access, Collect IDs and scan requests always go through Burp. The OAuth checks send their authorization-server requests through Burp but outside its scan queue, so a server's `RateLimit-*` headers cannot make Burp slow down the whole scan. Burp refuses streamed (`text/event-stream`) replies to extensions, so a few requests always go directly even with the setting on: the legacy SSE event stream, the retry of a probe whose reply Burp refused as a stream, and probes that must read an open stream. Burp's upstream proxy does not apply to those. There is no workaround while Burp withholds streamed replies from extensions.
- **SSE proxy port**: the local SSE proxy binds to an ephemeral loopback port. Firewall or network policies that block loopback traffic will break SSE-transport scans.
- **OAuth callback port**: the OAuth callback listener defaults to an ephemeral port (port 0). If your authorization server requires strict redirect-URI pre-registration, set a fixed callback port in the OAuth section before initiating the flow.
- **Project file sensitivity**: tool toggles, the user list and owned values (without credentials), the shared OAuth client settings, dynamic-registration client URIs and the **Test OAuth consent with my sign-in** choice are persisted in the Burp project file (cookies used for that test stay in Burp's cookie jar), never in your Burp user preferences, which hold only the settings you save as your defaults. Dynamic-registration management tokens stay in memory only, so **Copy management token** works until the extension unloads; tokens saved by earlier versions are deleted when the project loads. Issue evidence is the raw exchange, so issues Burp saves in the project can hold the bearer tokens, API keys, OAuth tokens and client secrets that were sent or returned. Treat the project file as sensitive and restrict access accordingly.
- **Check access precision**: an object or tool every user may legitimately read (a global help tool, a team document) can show a possible finding on the Access grid. Set its **Who should reach it** to **Anyone — same result for everyone** in the Access tab. Replaying write tools as another identity needs the same confirmation as Scan.
- **Auth-bypass check on SSE transport**: the SSE event stream remains authenticated while an operation POST is tested without credentials. An accepted POST therefore does not by itself prove that the server permits a fully unauthenticated session. The auth-bypass check is fully reliable on Streamable HTTP transport.

## Troubleshooting

**OAuth 401 loops** — usually a clock-skew or audience-mismatch issue. Check the Logger sub-tab for refresh failures and verify that the token audience matches the resource server's expected value. On initialize-based transports, also verify that `Mcp-Session-Id` is round-tripping through the proxy.

**SSE handshake hangs** — confirm the local proxy port is reachable from Burp's scanner. Check the Logger sub-tab for proxy startup errors or connection failures.

**`tools/list` fails** — check the Logger sub-tab for the selected protocol version and catalog error. Initialize-based servers may require `Mcp-Session-Id`; modern servers use `server/discover` and do not have a protocol session ID.

**JAR loads but no tab appears** — open Burp's **Extender** output panel and look for a stack trace. The most common causes are a Java version mismatch (requires Java 17+) or a conflicting dependency already loaded by another extension.
