# MCP Server Scanner Extension

A Burp Suite extension for security-testing [Model Context Protocol](https://modelcontextprotocol.io) servers.

Discovers MCP tools, resources, resource templates, and prompts, builds JSON-RPC 2.0 requests with fuzzable insertion points, and runs them through Burp's active and passive scanners.

> **Requires Burp Suite Professional.** Every check is driven by Burp's Scanner (active and passive audits), which is not present in Burp Community Edition. The extension loads in Community but cannot scan — discovery may work, but no audit checks will run. Burp Collaborator (also Professional-only) is additionally required for the out-of-band RCE check.

## Features

- **Protocol and transports:** Auto detects modern `server/discover` HTTP, initialize-based Streamable HTTP, then legacy SSE. Explicit modes are available. A local proxy lets Burp's scanner consume `text/event-stream` replies.
- **Auth:** each user has its own credentials: none, a bearer token, custom headers, or an OAuth 2.1 sign-in with PKCE. All OAuth users sign in through one shared OAuth client. It supports pre-registered clients, hosted Client ID Metadata Documents, and legacy dynamic client registration, with protected-resource and OAuth/OIDC authorization-server discovery.
- **Access control between users:** scan as one user and compare what other users can list, call and read.
- **Active checks:** 17 scan checks, listed under [Checks](#checks).

Aimed at MCP server **operators** auditing their own deployments.

## Checks

Each check has a toggle in the **Scan Checks** tab. Severity is the headline rating; a check that reports several findings lists each one.

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
| MCP OAuth redirect policy | per host | Medium / Firm when an authorization code reaches an unregistered redirect URI; Information for error redirects, script-scheme registration and wildcard expansion |
| MCP OAuth consent page HTML structure reflection | per host | Information |
| **MCP OAuth authorization without login or consent** | per host | High / Certain when the code redeems to a token that opens a refused request; Medium / Firm when a code is issued with no login or consent page; Medium / Tentative when the server first created an anonymous session; Information when the endpoint already answers without a token |
| **MCP OAuth authorization code redeemed more than once** (part of the check above) | per host | Medium / Certain when a second sequential or concurrent redemption returns a working token |
| **MCP sibling route authentication parity** | per host | Low / Firm when the main route refuses a catalog listing without credentials and a sibling route (`/mcp_message`, `/messages`, `/message`, `/sse`, `/mcp/` and similar) or the advertised legacy SSE message route answers it |
| **MCP session lifecycle** | per host | High / Firm when probe session IDs are guessable (repeated, increasing, known time-based formats — UUID v1/v6/v7, ULID, KSUID, Snowflake, ObjectId — whose clock and counter fields leave under 64 random bits, or under 64 varying bits after hex/base64 decoding; up to 30 probe sessions when the first eight are borderline) and a bare ID runs a request without credentials; Low / Firm for guessable IDs alone (Tentative when only the live session's ID repeats); Low / Firm when a session still answers ping, or still opens its GET event stream (while a never-issued ID's stream is refused), after a successful DELETE. Runs only when the server issues `Mcp-Session-Id`, or on legacy SSE (guessability only, on probe streams of its own, skipped when the message route carries no session id); uses its own probe sessions and never touches the scanner's |

## Build

```bash
./gradlew shadowJar
```

Output: `build/libs/mcp-server-scanner-extension-2.1.2-all.jar`.

Requires Java 17.

## Install

In Burp: **Extensions → Installed → Add → Java**, then select the fat JAR above.

Open the **MCP Server Scanner** tab, enter the server endpoint, and connect. Connect, discovery and Scan run as the **primary user**, shown next to the Connect button as **as [User 1 · Detect automatically ▾]**. A new project's User 1 is set to **Detect automatically**: Connect tries without credentials, signs in with OAuth if the server advertises it, and if the server refuses, a strip under the endpoint asks for a bearer token right there and reconnects with it. Credentials are per user and live in the **Users** tab.
Leave **Transport** on **Auto** unless you need to force a specific protocol family. The descriptions beneath the controls explain the supported versions and authentication choices. Protocol dates are negotiated automatically. After connecting, **Server Info → Connection** shows the selected mode, actual transport and protocol version, effective endpoint, and authentication mode, even after scan status changes. Existing saved Streamable HTTP and SSE choices still load.

For OAuth, the **OAuth client** section of the **Client** tab is shared by every user who signs in with OAuth. The issuer is discovered from the MCP server unless you enter one. Choose **Auto** registration when the server advertises a usable method. Use **Pre-registered** when you have a client ID from the authorization server, or **Client ID Metadata Document** when you host a public HTTPS client metadata document. Use **Dynamic registration** only with servers that still expose a registration endpoint. The OAuth callback uses a loopback address; set a fixed callback port when the server requires an exact registered redirect URI. The OAuth client is locked while connected. The rest of the Client tab sets how the extension presents itself in the MCP handshake and in dynamic registration. For a machine-to-machine server, set the primary user's auth to **OAuth client credentials** (or **OAuth enterprise-managed**, when an identity provider plugin is installed) and fill in its grant settings in the Users tab.

Use **Send to Repeater** on a discovered tool, resource, template, or prompt to edit and replay a request. The local proxy supplies the primary user's credentials and transport session headers when sending it upstream.

### Testing access control between users

The **Users** tab has the **Primary user** and the **Compared users**. Each compared user has a name, its access compared with the primary user (**Same (peer)**, **Less access** or **More access**) and its own credentials. Add one with **Add user ▾**: a bearer token, custom headers, an OAuth 2.1 sign-in, or no credentials. **Sign in all** signs in every OAuth user that needs it. Credentials stay in memory and are never saved to the project. Secret fields are masked; click the eye to show a value.

Pick the primary user from the menu beside Connect, or with **Make primary user** in a compared user's editor. While connected, changing it asks whether to reconnect. On **Reconnect**, running scans stop and the scanner session restarts as the new user. The previous primary user becomes a compared user. **Detect automatically** and the OAuth grant kinds belong to the primary user only.

Tick **Compare** for the users to compare with the primary user. **Anonymous** is always included as a comparison with no credentials.

Each user can also have an optional **Private marker:** text only that user should ever see. When it shows up in another user's result, that is evidence of a leak.

Each user also keeps **owned values**: argument names with that user's own ids, such as `documentId → 42`. Tools that take an object id need a real one. A made-up id fails for every user, so an access bug stays hidden. A value is either **entered** (typed in, or owned objects saved by an earlier version) or **collected** from the server's replies by **Collect IDs** in the Access tab, in which case it records the operation and field it came from and whether it is **private** to that user or **shared** with others. Owned values are saved in the Burp project, never with reply text or credentials, and collected ones can be removed with "Clear collected IDs…" for one user or all. For each argument a tool call uses the user's first entered value, else its first private collected value; shared values are never used as owned ids.

After Connect, each compared user lists the server's tools and resources in its own MCP session. The **Access** tab shows what each user lists. After **Check access**, it also shows what each can call. Set **Who should reach it** per item, and mark items **Anyone — same result for everyone** to silence them.

Cross-user testing is **Check access**, not a scan check. Check access sends each item as its owner (with the owner's owned values in place of schema defaults, as Scan does), then as every compared user and anonymously, and reports:

- a lower-privilege user reaching an operation its expectation forbids (also retried at older MCP protocol versions when refused), filed in Burp as High;
- one user's private marker in another user's result, filed as High / Firm;
- the owner's credentials reaching another user's object by that user's owned id (entered or collected): filed as High / Firm only when that user's private marker appears, otherwise shown on the Access grid as a possible finding.
- another user getting the owner's exact result for a call that carries one of the owner's own values, when the same call with an invented value of the same shape is refused: shown on the Access grid as a possible finding (Tentative); filed as High / Firm only when the owner's private marker appears.

**Ratings:** collected IDs alone never file a Burp issue. A Firm object-level issue needs a private marker you entered; without one the Access grid shows a Tentative possible finding. Another credential running in a user's MCP session is the separate **session binding** scan check, listed in the Scan Checks tab.

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

- **Burp Suite Professional required**: every check runs through Burp's Scanner (active/passive audits), which Community Edition does not include. In Community the extension loads and can connect/discover, but no scan checks will run. There is no Community-compatible mode.
- **Collaborator-backed checks**: within Professional, the command-injection check's out-of-band payloads, the outbound-request check and the SSRF address filter bypass check require Burp Collaborator. Without Collaborator they produce no out-of-band findings.
- **SSE proxy port**: the local SSE proxy binds to an ephemeral loopback port. Firewall or network policies that block loopback traffic will break SSE-transport scans.
- **OAuth callback port**: the OAuth callback listener defaults to an ephemeral port (port 0). If your authorization server requires strict redirect-URI pre-registration, set a fixed callback port in the OAuth section before initiating the flow.
- **Project file sensitivity**: tool toggles, the user list and owned values (without credentials), the shared OAuth client settings and dynamic-registration client URIs are persisted in the Burp project file. Dynamic-registration management tokens stay in memory only, so **Copy management token** works until the extension unloads; tokens saved by earlier versions are deleted when the project loads. Treat the project file as sensitive and restrict access accordingly.
- **Check access precision**: an object or tool every user may legitimately read (a global help tool, a team document) can show a possible finding on the Access grid. Set its **Who should reach it** to **Anyone — same result for everyone** in the Access tab. Replaying write tools as another identity needs the same confirmation as Scan.
- **Auth-bypass check on SSE transport**: the SSE event stream remains authenticated while an operation POST is tested without credentials. An accepted POST therefore does not by itself prove that the server permits a fully unauthenticated session. The auth-bypass check is fully reliable on Streamable HTTP transport.

## Troubleshooting

**OAuth 401 loops** — usually a clock-skew or audience-mismatch issue. Check the Logger sub-tab for refresh failures and verify that the token audience matches the resource server's expected value. On initialize-based transports, also verify that `Mcp-Session-Id` is round-tripping through the proxy.

**SSE handshake hangs** — confirm the local proxy port is reachable from Burp's scanner. Check the Logger sub-tab for proxy startup errors or connection failures.

**`tools/list` fails** — check the Logger sub-tab for the selected protocol version and catalog error. Initialize-based servers may require `Mcp-Session-Id`; modern servers use `server/discover` and do not have a protocol session ID.

**JAR loads but no tab appears** — open Burp's **Extender** output panel and look for a stack trace. The most common causes are a Java version mismatch (requires Java 17+) or a conflicting dependency already loaded by another extension.
