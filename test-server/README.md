# mcp-test-server

An intentionally vulnerable MCP server and OAuth authorization server. The
[Burp MCP Server Scanner extension](../) uses it as its local test target.

Every vulnerability that a v1 check targets is a separate module with two modes:

- **vulnerable:** the check should fire.
- **safe:** the fixed behaviour. The check should stay silent.

You can set each vulnerability's mode at startup or change it at runtime, so one
running server can show a check both firing and staying silent.

> Do not expose this server to an untrusted network. In vulnerable mode it runs shell
> commands, evaluates code and reads arbitrary files.

## Run

```bash
cd test-server
uv sync
uv run mcp-test-server --host 127.0.0.1 --port 8000          # every vuln vulnerable
uv run mcp-test-server --default-mode safe                    # every vuln safe
uv run mcp-test-server --list-vulns                           # names and summaries
```

To run it in a container:

```bash
docker compose up --build                                     # http://127.0.0.1:8000
MCP_TEST_DEFAULT_MODE=safe MCP_TEST_VULNS=traversal_plain=vulnerable docker compose up
```

The endpoints are:

- Streamable HTTP: `POST /mcp` (also served on `/message`, guarded the same way unless `auth_sibling_route` is vulnerable)
- Legacy SSE: `GET /sse`, then `POST /messages?session_id=…`
- OAuth authorization server: on the same origin

## Configuration interface

Settings are read from four layers. Later layers override earlier ones, and
`vulns` is merged per name across layers.

1. A JSON file: `--config FILE` or `MCP_TEST_CONFIG=FILE`
2. Environment variables: `MCP_TEST_<KEY>`
3. CLI flags
4. At runtime: `PUT /_test/vulns`

| Setting | CLI | Environment | Default |
|---|---|---|---|
| Mode of every vuln not named | `--default-mode vulnerable\|safe` | `MCP_TEST_DEFAULT_MODE` | `vulnerable` |
| Mode of one vuln | `--vuln NAME=MODE` (repeatable) | `MCP_TEST_VULNS=a=safe,b=vulnerable` | — |
| Switch off a request family or transport | `--disable-family FAMILY` (repeatable) | `MCP_TEST_DISABLED_FAMILIES=ping,sse` | none |
| List page size (forces cursors) | `--page-size N` | `MCP_TEST_PAGE_SIZE` | `3` |
| `Mcp-Session-Id` policy | `--sessions required\|optional\|off` | `MCP_TEST_SESSIONS` | `required` |
| Streamable HTTP reply format | `--response-mode json\|sse` | `MCP_TEST_RESPONSE_MODE` | `json` |
| Consent at `/authorize` | `--consent prompt\|auto` | `MCP_TEST_CONSENT` | `prompt` |
| Issuer, audience and metadata base URL | `--public-url URL` | `MCP_TEST_PUBLIC_URL` | `http://HOST:PORT` |
| Hosts that safe Origin/Host admission accepts | `--allowed-host H` (repeatable) | `MCP_TEST_ALLOWED_HOSTS` | `localhost,127.0.0.1,::1` |
| Sandbox base directory | `--files-dir DIR` | `MCP_TEST_FILES_DIR` | a new temp dir |
| JSONL request log | `--request-log FILE` | `MCP_TEST_REQUEST_LOG` | off |
| Shell, node and eval timeout (s) | `--command-timeout` | `MCP_TEST_COMMAND_TIMEOUT` | `30` |
| Outbound fetch timeout (s) | `--fetch-timeout` | `MCP_TEST_FETCH_TIMEOUT` | `3` |
| Enabled MCP protocol versions | `--protocol-version V` (repeatable, replaces the default) | `MCP_TEST_PROTOCOL_VERSIONS=2025-06-18,2025-03-26` | all five known versions |

The config file uses the same keys, for example:
`{"default_mode": "safe", "vulns": {"jwt_alg_none": "vulnerable"}, "disabled_families": ["sse"],
"protocol_versions": ["2026-07-28"]}`. An unknown protocol version stops the server at startup.

To change modes at runtime without a restart:

```bash
curl -X PUT localhost:8000/_test/vulns -d '{"traversal_plain":"safe","jwt_alg_none":"vulnerable"}'
curl -X PUT localhost:8000/_test/vulns/traversal_plain -d '{"mode":"vulnerable"}'
curl localhost:8000/_test/vulns              # [{name, mode, summary}, ...]
```

### Auth interaction

`unauthenticated_execution` decides only what happens when a request has **no**
`Authorization` header:

- **vulnerable:** the request executes.
- **safe:** the server answers 401 with `WWW-Authenticate: Bearer resource_metadata=…`.

A request that carries a bearer token is always checked by the JWT verifier, and the
`jwt_*` modules relax that verifier. A JWT check that needs the missing-credential
control refused should set `unauthenticated_execution=safe`.

## Vulnerability catalogue

The surfaces and the vulnerable and safe behaviour of each module are listed below.
Each module lives at `src/mcp_test_server/vulns/<family>/<name>.py`.

### Unauthenticated execution

| Name | Surface | Vulnerable | Safe |
|---|---|---|---|
| `unauthenticated_execution` | Every method on `/mcp`, `/sse` and `/messages`, notifications included | Requests without credentials execute | 401 challenge |
| `auth_forwarded_loopback_trust` | Every guarded path and method | A request without credentials executes when the first hop of `X-Forwarded-For` or `X-Real-IP` is `127.0.0.1`, `::1` or `localhost` | 401 challenge |
| `auth_session_credential` | Every guarded path and method | An `Mcp-Session-Id` that was once sent with a valid bearer token authenticates later requests without credentials | 401 challenge |
| `auth_presence_only_credential` | Every guarded path and method | Any non-empty bearer token is accepted; only its presence is checked (the LiteLLM CVE-2026-59822 and meta-ads 1.0.109 shape) | 401 `invalid_token` challenge |
| `auth_sibling_route` | `/message`, which serves the same Streamable HTTP handler as `/mcp` | Requests without credentials execute on `/message` while `/mcp` still challenges | 401 challenge on both |

The bypass and presence-only modules only matter when `unauthenticated_execution=safe`; with it vulnerable every anonymous request executes anyway.

### JWT acceptance

Valid tokens are RS256 with:

- `iss` = base URL
- `aud` = base URL + `/mcp`
- `exp` in the future

Mint one with `POST /_test/mint-token`.

| Name | Vulnerable: accepts | Safe |
|---|---|---|
| `jwt_forged_signature` | RS256 with any signature (an attacker's key) | Rejected |
| `jwt_alg_none` | `alg: none` with an empty signature | Rejected |
| `jwt_hs256_key_confusion` | HS256 HMAC-keyed with the server's RSA public key PEM (`/public-key.pem`, with or without the trailing newline). A wrong HMAC key is still rejected | Rejected |
| `jwt_empty_key_unknown_kid` | HS256 with a `kid` other than the server's and an empty HMAC key, the shape of fast-jwt CVE-2026-44351 (an async key resolver returning `''`). The server's own `kid`, a missing `kid` or a non-empty wrong key are still rejected | Rejected |
| `jwt_wrong_audience` | Any `aud` | Rejected |
| `jwt_wrong_issuer` | Any `iss` | Rejected |
| `jwt_expired` | `exp` in the past or missing | Rejected |

Each weakness relaxes only its own rule; they do not combine on their own. For
example, a wrong-issuer token signed with a random key is still rejected unless
`jwt_forged_signature` is also vulnerable.

### Origin/Host admission

These apply on `/mcp`, `/sse` and `/messages`.

| Name | Vulnerable | Safe |
|---|---|---|
| `origin_admission` | Any `Origin` (including `null`) executes | 403 `invalid Origin header` unless the Origin's host is an allowed host. No Origin is fine |
| `host_admission` | Any `Host` executes | 403 `invalid Host header` unless the host is an allowed host |

### File traversal

There are three variants. Each one registers the same four surfaces:

| Surface | Name pattern | Field |
|---|---|---|
| Tool | `read_file_<v>` | argument `path` |
| Header-driven tool | `read_document_<v>` | request header `X-Document-Path` |
| Prompt | `review_file_<v>` | argument `path` |
| Resource | `<scheme>://<root>/readme.txt` (encoded: `encoded-file:///readme.txt`) | — |
| Resource template | `<scheme>:///{+path}` | `path` |

For `plain` and `prefix`, a resource URI's path is absolute, as in a real `file://`
URI. So `file:///etc/passwd` means `/etc/passwd`. For `encoded`, the URI path is
relative to the root, because the variant rejects a leading `/` by design.

| Name | `<v>` | `<scheme>` | Vulnerable | Safe |
|---|---|---|---|---|
| `traversal_plain` | `plain` | `file` | Joined to the root without checks; absolute paths and `file://` are honoured | realpath + commonpath containment |
| `traversal_encoded` | `encoded` | `encoded-file` | Literal `../`, `..\` and leading `/` are rejected, then the value is URL-decoded once and read (`%2e%2e%2f` escapes) | Same literal check, then containment after decoding |
| `traversal_prefix_sibling` | `prefix` | `prefix-file` | `normpath(...).startswith(root)` containment (the CVE-2025-53110 shape) | commonpath containment |

The sandbox layout, under `--files-dir`:

- The root is `<base>/workspace`, containing `readme.txt` and `notes/todo.txt`.
- `<base>/outside-secret.txt` contains `OUTSIDE-ROOT-SECRET-7d1f2c`.
- In the container, `/etc/passwd` provides the `root:x:0:0:` signature.

Error strings are fixed so checks can match them:

| Condition | Error text |
|---|---|
| Denied | `Error: Access denied - path outside allowed directories: <value> not in <root>` |
| Missing parent | `Error: Parent directory does not exist: <parent>` |
| Missing file | `Error: ENOENT: no such file or directory, open '<path>'` |

Where errors appear:

- Tools return errors with `isError: true`.
- Prompts and resources return the error text inside a successful result.

The prefix-sibling differential works like this:

- `/bs2-x/missing` gives "Access denied" in both modes.
- `<root>_bs2_x/missing` gives "Parent directory does not exist" when vulnerable and "Access denied" when safe.

### Command injection

| Name | Tool (argument) | Vulnerable | Safe |
|---|---|---|---|
| `shell_command_injection` | `ping_host` (`host`) | `sh -c "ping -c 1 -W 1 <host>"` and returns the output. `; printf mcp%s $((20+22)) #` gives `mcp42` | Hostname regex, then argv `ping` |
| `blind_shell_command_injection` | `archive_logs` (`label`) | `sh -c "tar -cf /tmp/mcp-test-archive-<label>.tar /dev/null >/dev/null 2>&1"`; always answers `archive queued`, so only an out-of-band effect (DNS/HTTP callback, file write) shows the injection | Label regex `^[A-Za-z0-9_-]{1,64}$`; nothing is run |
| `sql_table_injection` | `count_rows` (`table`) | `SELECT COUNT(*) FROM <table>` on an in-memory SQLite database (tables `notes`, `secrets`); `notes/*q*/` counts `notes`, `notes/q**/` is a syntax error | Table must exist (bound `sqlite_master` lookup), then double-quoted |
| `sql_literal_injection` | `find_note` (`title`) | `SELECT body FROM notes WHERE title = '<title>'`; `first' -- q` returns `alpha` like `first` | Bound parameter |
| `python_eval_injection` | `calculate` (`expression`) | Python `eval()`, run in a separate worker process and bounded by `--command-timeout` so the server never stalls | AST arithmetic only |
| `javascript_eval_injection` | `render_greeting` (`template`) | `node` evaluates the value as a JS template literal. `${require('child_process').execSync(...)}` runs | Substitutes only `${name}` and `${product}` |

### Outbound fetch

Each module fetches every string value of the right shape from its fields:

- an `http(s)://` URL, fetched as given
- a bare `host.tld[:port][/path]`, fetched as `http://…`

Fetches in safe mode never happen. Every attempt is recorded at `GET /_test/fetches`
as `{source, path, url, time}`.

| Name | Fields |
|---|---|
| `fetch_tool_arguments` | Tool `fetch_document`: every argument leaf, recursively. The `options.timeout_seconds` integer and the `options.tags[]` array are there so tests cover numeric-typed and nested leaves. When safe, it returns an allowlist error |
| `fetch_resource_uri` | `resources/read` `params.uri` |
| `fetch_list_cursor` | `params.cursor` on every `*/list` |
| `fetch_meta` | Every leaf under `params._meta` on any request or notification |
| `fetch_client_info` | Every `initialize` param except `_meta`: `clientInfo.*`, including `websiteUrl` and `icons[].src`, plus capabilities |
| `fetch_headers` | Every request header except `Host`, `Origin`, `Content-Length` and `Connection` |
| `fetch_oauth_client_metadata` | DCR `client_uri`, `logo_uri` and `jwks_uri` |

### Downstream route escape

| Name | Surface | Vulnerable | Safe |
|---|---|---|---|
| `downstream_route_escape` | Tool `get_license` (`license_id`). It builds the downstream path `/api/v1/licenses/<id>` on the same host, which is also served over HTTP at `/downstream/...` | URL-decodes the id, then `posixpath.normpath`. `../token` reaches `/api/v1/token` | Percent-encodes the id as a single segment |
| `downstream_raw_segment` | Tool `get_invoice` (`invoice_id`) against the in-process billing API `/api/v2/invoices/<id>` | Joins the id raw, then `posixpath.normpath`. `../` reaches the non-error service index at `/api/v2` | Percent-encodes the id as a single segment |
| `downstream_encoded_dot_segment` | Tool `get_order` (`order_id`) against `/api/v2/orders/<id>` | Percent-encodes the id (as `encodeURIComponent` does), then resolves dot segments, so only a bare `..` reaches the service index | Rejects `.` and `..` as a tool error |

The protected routes `/api/v1/token` and `/api/v1/admin/users` contain the marker
`downstream-protected-marker-4931`. Known ids are `LIC-1001` and `LIC-1002`.

The billing service index (`billing-service-index`) is the non-error API root the route-escape check's differential tier needs. Known billing ids are `INV-1001` and `ORD-2001`.

Unknown ids return the non-error text `{"error": "not found"}`. That keeps the normal
and missing controls non-error in both modes.

### Cross-identity access control

Three static bearer users are always accepted by the credential gate, beside minted JWTs.
No flag is needed; like the preconfigured OAuth clients, they are fixture identities.

| User | Role | Token (`Authorization: Bearer …`) | Owns |
|---|---|---|---|
| `alice` | admin | `alice-token` | document `d-alice-0001`, `notes://alice/private.md` (marker `ALICE-PRIVATE-7f3c`) |
| `bob` | member | `bob-token` | document `d-bob-0042`, `notes://bob/private.md` (marker `BOB-PRIVATE-91ad`) |
| `carol` | reader | `carol-token` | nothing |

Any other bearer value is still verified as a JWT, so `mallory-token` gets 401. A request with
no credentials gets 401 when `unauthenticated_execution=safe` (as under `--default-mode safe`).
When the gate does admit an anonymous request, the identity tools answer
`Error: authentication required` (`isError: true`) and the identity resources a JSON-RPC
`-32600` error. The identity tools and resources are listed only to the three users, so an
anonymous or JWT caller's listing is unchanged.

| Name | Surface | Listed to | Vulnerable | Safe |
|---|---|---|---|---|
| `cross_identity_object` | Tool `get_document` (`doc_id`) | every user | Any user reads any document (the NextCRM CVE-2026-55544 IDOR) | Non-owner gets `Error: document <id> not found`, the same as an unknown id |
| `cross_identity_resource` | `resources/read` of `notes://alice/private.md`, `notes://bob/private.md` | the owner only | Any user reads either note | Non-owner gets `-32002` `Resource not found` |
| `cross_identity_role` | Tools `delete_project` (`project_id`) and `list_users` | `delete_project`: alice, bob; `list_users`: alice | Hidden tools still run for lower roles with the owner's result shape (the Obot / MCPHub shape) | `Error: forbidden - role <role> may not call this tool` |
| `cross_identity_session` | Streamable HTTP `Mcp-Session-Id`, read through tool `whoami` | every user | A session opened by alice runs bob's request in alice's session context: `whoami` with `bob-token` and alice's session id answers `alice` (the MCP Python SDK CVE-2026-52869 shape) | 404 `Unknown session` for a session presented with another principal's credential |

`delete_project` never changes state: it always answers `project <id> scheduled for deletion`.
`list_users` answers `alice (admin)`, `bob (member)` and `carol (reader)` on separate lines.
Every result is deterministic, so replays compare equal.

Two negative controls are correct in every mode: tool `search_docs` (`query`) returns the same
shared result to every user, and `notes://team/handbook.md` is listed to and readable by every user.

Session binding applies only to Streamable HTTP. Legacy SSE channels and sessionless modern
(2026-07-28) requests have no session to bind; `whoami` then names the token's user.

To test a cross-identity check end to end:

```bash
uv run mcp-test-server --default-mode safe --vuln cross_identity_object=vulnerable \
  --vuln cross_identity_resource=vulnerable --vuln cross_identity_role=vulnerable \
  --vuln cross_identity_session=vulnerable
```
### OAuth authorization server

The discovery and key endpoints are:

- `/.well-known/oauth-authorization-server`
- `/.well-known/openid-configuration`
- `/.well-known/oauth-protected-resource[/mcp]`
- `/jwks.json`
- `/public-key.pem`

The flow endpoints are:

| Endpoint | Behaviour |
|---|---|
| `POST /register` | Anonymous DCR. Gives a confidential client when `token_endpoint_auth_method` is not `none` |
| `GET /authorize` | PKCE S256 required. Supports `response_mode=fragment`, `prompt=none` (→ `error=consent_required`) and RFC 9207 `iss` |
| `POST /authorize/consent` | Approve or deny |
| `POST /token` | `authorization_code` and `refresh_token`, with client auth by Basic or form |

With `--consent auto`, `/authorize` redirects with a code straight away. Use it for
redirect-policy code-delivery tests. With `prompt` (the default), it renders the
consent page. Use that for reflection tests.

Two clients are preconfigured:

| Client | Type | Secret | Redirect URIs |
|---|---|---|---|
| `public-client` | Public | — | `https://client.example/callback`, `http://127.0.0.1/callback` |
| `confidential-client` | `client_secret_basic` | `confidential-secret` | `https://client.example/callback`, `http://127.0.0.1/callback` |

Loopback `http` redirect URIs match any port (RFC 8252).

A `redirect_uri` that is not registered is sorted into one shape, and only that
shape's module decides whether it is accepted. That way, setting one redirect module
to safe is never overridden by another:

| Shape | Deciding module |
|---|---|
| `javascript:`, `data:` or `vbscript:` | `redirect_script_scheme_registration` |
| Matches a registered wildcard | `redirect_wildcard_registration` |
| `http://` twin of a registered URI | `redirect_http_downgrade` |
| Extends or normalises to a registered URI | `redirect_path_normalisation` |
| Anything else | `redirect_unregistered` |

| Name | Vulnerable | Safe |
|---|---|---|
| `redirect_unregistered` | `/authorize` accepts any `redirect_uri` | Exact match (loopback ignores the port) → 400 page, no redirect |
| `redirect_http_downgrade` | `http://` twin of a registered `https://` URI accepted | 400 |
| `redirect_path_normalisation` | A URI that extends a registered one (`<registered>/../x`) or normalises to it is accepted | 400 |
| `redirect_script_scheme_registration` | DCR accepts `javascript:`, `data:` and `vbscript:`, and `/authorize` redirects to them | DCR 400 `invalid_redirect_uri` |
| `redirect_wildcard_registration` | DCR accepts `https://*.host/cb`, and `/authorize` fnmatches it | DCR 400 |
| `consent_client_name_reflection` | `client_name` raw in `<h1>`, a quoted `value="…"` attribute and the `window.__CONSENT__` script object | HTML-escaped, and `<`-escaped in the script |
| `consent_state_reflection` | `state` raw in the same three contexts | Escaped |
| `refresh_missing_client_secret` | Confidential-client refresh succeeds with no secret (or an empty one) | 401 `invalid_client` |
| `refresh_wrong_client_secret` | Confidential-client refresh succeeds with a wrong secret | 401 |
| `refresh_scope_expansion` | `scope` wider than the grant is issued | 400 `invalid_scope` |

An unknown `client_id` gives a 400 page that does not reflect any input. That is the
reflection check's invalid-client control.

## Request families

Each family can be switched off with `--disable-family`. A disabled method returns
JSON-RPC `-32601`, and its capability is dropped from `initialize`.

- A disabled notification is still accepted with 202, because a notification has no reply.
- A disabled transport is not mounted, so it returns 404. The Origin/Host and credential
  gates run first, so a request they refuse still gets 403 or 401.

| Family | Method / surface |
|---|---|
| `tools_call` | `tools/call` |
| `resources_read` | `resources/read` (static resources) |
| `resource_templates_read` | `resources/read` of a templated URI |
| `prompts_get` | `prompts/get` |
| `tools_list` | `tools/list` (cursor) |
| `resources_list` | `resources/list` (cursor) |
| `resource_templates_list` | `resources/templates/list` (cursor) |
| `prompts_list` | `prompts/list` (cursor) |
| `initialize` | `initialize` |
| `notification_initialized` | `notifications/initialized` |
| `notification_cancelled` | `notifications/cancelled` |
| `notification_progress` | `notifications/progress` |
| `notification_roots_list_changed` | `notifications/roots/list_changed` |
| `completion` | `completion/complete` (prompt and template refs) |
| `logging` | `logging/setLevel` |
| `ping` | `ping` |
| `subscribe` | `resources/subscribe`, `resources/unsubscribe` |
| `server_discover` | `server/discover` (only when a modern version is enabled; needs no session) |
| `streamable_http` | `/mcp` (POST; DELETE ends a session; GET gives 405) |
| `sse` | `/sse` + `/messages` |

Other protocol details:

- **Protocol versions:** the known versions are 2026-07-28 (the stateless "modern" era, SEP-2575)
  and the handshake-era 2025-11-25, 2025-06-18, 2025-03-26 and 2024-11-05. `--protocol-version`
  chooses which are enabled, so a client can be tested against each one.
- **`initialize`:** never negotiates a modern version. It answers the requested version when that
  is an enabled handshake version, and otherwise the newest enabled handshake version. With no
  handshake version enabled it returns `-32602` `Unsupported protocol version` with
  `data: {"supported": [...enabled...]}` and opens no session.
- **`server/discover`:** with a modern version enabled it returns `supportedVersions` (the enabled
  modern versions), `capabilities`, `serverInfo`, `instructions`, `ttlMs: 0`,
  `cacheScope: "private"` and `resultType: "complete"`. Without one it is `-32601`, as on a legacy server.
- **`MCP-Protocol-Version` header:** a value that is not an enabled version gives 400.
- **Modern requests on `/mcp`:** a request (not a notification) whose `params._meta` carries
  `io.modelcontextprotocol/protocolVersion` is checked as follows. Every refusal is HTTP 400 with a
  JSON-RPC error.
  - `_meta` must hold a string `io.modelcontextprotocol/protocolVersion` and an object
    `io.modelcontextprotocol/clientCapabilities` (`io.modelcontextprotocol/clientInfo` is optional
    but must be an object); otherwise `-32602` naming the key.
  - The `_meta` version must be an enabled modern version; otherwise `-32602`
    `Unsupported protocol version` with the enabled modern versions as `data.supported`.
  - `MCP-Protocol-Version` must equal the `_meta` version, and `Mcp-Method` must be present and equal
    the body method; otherwise `-32020` (header mismatch).
  - For `tools/call`, `resources/read` and `prompts/get`, `Mcp-Name` must be present and equal
    `params.name` or `params.uri`. A value of the form `=?base64?<b64>?=` is decoded first.
    Otherwise `-32020`.
  - A request whose `MCP-Protocol-Version` header is a modern version but which carries no envelope
    gives `-32602`. `server/discover` and notifications are exempt.
  - Modern requests are sessionless: `Mcp-Session-Id` is neither required nor checked, and none is issued.
- **Legacy SSE** (`/sse` + `/messages`) serves the handshake-era versions only.
- **Batches:** JSON-RPC batches are answered as batches.
- **Sessions, when `required`:** a missing `Mcp-Session-Id` gives 400 and an unknown one gives 404. `initialize`, `server/discover` and modern requests are exempt.

## Inspection endpoints

These endpoints have no auth and are not logged.

| Endpoint | Purpose |
|---|---|
| `GET` / `DELETE /_test/requests` | Every received request, including ones rejected by auth or admission. Each entry has `seq`, `time`, `http_method`, `path`, `query`, `headers`, `status`, and `messages[]` with `method`, `id`, `notification`, `params` and `param_paths`. `param_paths` lists every leaf, such as `params.arguments.options.tags[0]` and `params._meta.progressToken` |
| `GET` / `DELETE /_test/fetches` | Outbound fetch attempts |
| `GET` / `PUT /_test/vulns`, `PUT /_test/vulns/{name}` | Read or change modes |
| `POST /_test/mint-token` | `{subject?, scope?, client_id?, claims?}` → a valid RS256 access token. `claims` overrides any claim |
| `GET /_test/settings` | The effective base URL, files root, disabled families and other settings |

`--request-log FILE` also appends each entry as JSONL.

## Develop

```bash
uv run pytest        # every vuln in both modes, plus every protocol family
uv run ruff check .
uv run mypy src
```

To add a vulnerability, add a module under `src/mcp_test_server/vulns/<family>/` with
a `Vulnerability` subclass that defines:

- `name`
- `summary`
- `contribute(surface)`

The registry discovers it automatically. Nothing else changes.

To relax an existing policy instead, subclass the family base and set `weakness`:
`JwtVulnerability`, `RedirectVulnerability` or `RefreshVulnerability`.

## HTTPS and mutual TLS (client certificates)

| Flag | Meaning |
|---|---|
| `--tls-cert PATH` | PEM server certificate. With `--tls-key`, the server serves HTTPS. |
| `--tls-key PATH` | PEM server private key (PKCS#8 or traditional). Required with `--tls-cert`. |
| `--tls-client-ca PATH` | PEM CA certificate. The server then **requires** a client certificate signed by this CA (mTLS) and rejects the TLS connection otherwise. Requires `--tls-cert` and `--tls-key`. |

A key without a certificate, a certificate without a key, or `--tls-client-ca`
without both is rejected at startup.

Exercises: the extension's Burp-backed Connect transport, which routes
Streamable HTTP / modern HTTP Connect traffic through Burp so a client
certificate configured in Burp is presented. Automated proof:
`MutualTlsTestServerIT` (`MCP_E2E_IT=1 ./gradlew test --tests MutualTlsTestServerIT`).

#### Manual check in Burp

```bash
mkdir -p /tmp/mtls && cd /tmp/mtls

# CA
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -days 7 \
  -subj "/CN=Test CA" -keyout ca.key -out ca.pem

# Server certificate for 127.0.0.1
openssl req -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes \
  -subj "/CN=localhost" -keyout server.key -out server.csr
openssl x509 -req -in server.csr -CA ca.pem -CAkey ca.key -CAcreateserial -days 7 \
  -extfile <(printf "subjectAltName=IP:127.0.0.1,DNS:localhost\nextendedKeyUsage=serverAuth") \
  -out server.pem

# Client certificate, exported as PKCS#12 for Burp
openssl req -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes \
  -subj "/CN=Test Client" -keyout client.key -out client.csr
openssl x509 -req -in client.csr -CA ca.pem -CAkey ca.key -CAcreateserial -days 7 \
  -extfile <(printf "extendedKeyUsage=clientAuth") -out client.pem
openssl pkcs12 -export -inkey client.key -in client.pem -certfile ca.pem \
  -passout pass:changeit -out client.p12

# Start the server requiring a client certificate
cd -   # back to test-server/
uv run mcp-test-server --host 127.0.0.1 --port 8443 \
  --tls-cert /tmp/mtls/server.pem --tls-key /tmp/mtls/server.key \
  --tls-client-ca /tmp/mtls/ca.pem
```

1. In Burp: **Settings → Network → TLS → Client TLS certificates → Add**,
   destination host `127.0.0.1`, type PKCS#12, file `/tmp/mtls/client.p12`,
   password `changeit`.
2. In the extension: make sure **Settings → Use Burp networking (client TLS
   certificates)** is on (the default; off, the client certificate is not
   presented). Then endpoint `https://127.0.0.1:8443/mcp`, transport
   Streamable HTTP, auth none, **Connect**.
   Expected: connects and lists the test-server's tools.
3. Remove (or disable) the client certificate in Burp and Connect again.
   Expected: Connect fails, and Burp's **Event log** shows the TLS error for
   `127.0.0.1:8443`.


