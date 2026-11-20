package com.mcpscanner.checks.catalog.unauthenticatedrequestexecution;

import com.mcpscanner.checks.issue.Cwe;

import java.util.List;

enum FindingKind {
    ANONYMOUS_EXECUTION(
            FindingKind.ANONYMOUS_EXECUTION_NAME,
            "The MCP server returned a successful result for this request after every credential and the "
                    + "scanner's session were removed. Anyone who can reach the endpoint can send the same request. "
                    + "The scan found no sign that the server requires authentication: no 401 challenge, no "
                    + "protected-resource metadata and no other request on this host refused without credentials. "
                    + "The server may be public by design, with any configured credential optional.",
            FindingKind.REQUIRE_AUTHENTICATION,
            List.of(new Cwe(306, "Missing Authentication for Critical Function"))),
    ANONYMOUS_EXECUTION_DESPITE_ENFORCEMENT(
            FindingKind.ANONYMOUS_EXECUTION_NAME,
            "The MCP server returned a successful result for this request after every credential and the "
                    + "scanner's session were removed, although it requires authentication elsewhere on this host: "
                    + "the last request in the evidence is a 401 challenge, protected-resource metadata or another "
                    + "request refused without credentials. Anyone who can reach the endpoint can send this request.",
            FindingKind.REQUIRE_AUTHENTICATION,
            List.of(new Cwe(306, "Missing Authentication for Critical Function"))),
    ANONYMOUS_CATALOG(
            "MCP catalog listed without authentication",
            "The MCP server listed its tools, resources, resource templates or prompts to a caller with no "
                    + "credentials. This tells an attacker which operations the server offers.",
            "If the catalog is not meant to be public, require authentication for list requests as well as for "
                    + "the operations they describe.",
            List.of(new Cwe(306, "Missing Authentication for Critical Function"))),
    AUTHENTICATION_BYPASS(
            "MCP authentication bypass",
            "The MCP server refused this request without credentials, but returned the same result as the "
                    + "authenticated request when the request was altered in a way that should not change who the "
                    + "caller is. The authentication layer and the MCP handler disagree about the request.",
            "Authenticate the request as the MCP handler will process it: normalise the path, method, headers "
                    + "and body before the authentication decision, and never trust client-supplied routing or "
                    + "client-address headers for authentication.",
            List.of(new Cwe(288, "Authentication Bypass Using an Alternate Path or Channel"))),
    SESSION_CREDENTIAL(
            "MCP session id accepted as credential",
            "The MCP server returned the same result after the request's credentials were removed while its "
                    + "Mcp-Session-Id was kept, but refused the same request without credentials in a fresh "
                    + "session. The session id alone authenticates the caller. The MCP specification says servers "
                    + "must not use sessions for authentication and must verify every inbound request.",
            "Authenticate every MCP request from its own credentials and bind each session to the principal "
                    + "that created it.",
            List.of(new Cwe(287, "Improper Authentication"))),
    INVALID_CREDENTIAL_ACCEPTED(
            "MCP invalid credential accepted",
            "The MCP server refused this request without a credential, but returned the same result as the "
                    + "authenticated request (for lists, a result with the same structure) when the credential was "
                    + "replaced with a fabricated value, and again with a second, different fabricated value. The "
                    + "evidence holds the baseline request, the refusal without a credential and the result for the "
                    + "first fabricated value; the second value's request is not attached. The server checks that "
                    + "a credential is present, not that it is valid, so any caller who sends an arbitrary "
                    + "credential can run this request. The scan does not show whether other requests "
                    + "depend on the credential, for example when the server passes it to an upstream service that "
                    + "validates it.",
            "Validate the credential itself before running the request (signature, expiry, audience, or a "
                    + "lookup against issued keys) and reject an invalid credential with HTTP 401.",
            List.of(new Cwe(287, "Improper Authentication"))),
    FORWARDED_CLIENT_ADDRESS_TRUSTED(
            "MCP source-address restriction trusts a client-supplied header",
            "The MCP server returned the scanner's result for this request, refused the same request when a "
                    + "client-address header (X-Forwarded-For, Forwarded, X-Real-IP or Client-IP) named the external "
                    + "address 203.0.113.7, and returned the result again when the header named 127.0.0.1, then "
                    + "refused 203.0.113.7 once more; that repeat is not attached: the evidence holds the baseline "
                    + "request, the first refusal and the admitted request. A refusal is an authentication refusal "
                    + "or another 4xx status other than 429, as the server sent it; server errors and proxy errors "
                    + "do not count. Every probe came from the scanner's own address, which the server allows, and "
                    + "carried the request's "
                    + "configured credentials. The server's decision to admit the request therefore depends on a "
                    + "header the client controls. The scan does not show that the header replaces the connection's "
                    + "address: a caller outside a source-address allowlist may be able to claim an allowed address, "
                    + "which a request from an address the server refuses would confirm. Any credential the request "
                    + "carries is still required. The scan does not show which addresses the server allows or "
                    + "whether a trusted proxy in front of it overwrites the header.",
            "Take the client address from the connection. Read forwarding headers only from configured trusted "
                    + "proxies, and only the entry the nearest trusted proxy appended.",
            List.of(new Cwe(290, "Authentication Bypass by Spoofing"),
                    new Cwe(348, "Use of Less Trusted Source"))),
    ANONYMOUS_STREAM(
            "MCP event stream opened without authentication",
            "The MCP server opened its server-to-client event stream (an HTTP GET with Accept: text/event-stream) "
                    + "for a request with no credentials, although it requires authentication elsewhere on this "
                    + "host: the last request in the evidence is a 401 challenge, protected-resource metadata or "
                    + "another request refused without credentials. The stream carries the server's notifications "
                    + "and requests to clients, so anyone who can reach the endpoint can subscribe to them.",
            FindingKind.AUTHENTICATE_THE_STREAM,
            List.of(new Cwe(306, "Missing Authentication for Critical Function"))),
    SESSION_STREAM(
            "MCP event stream opened with session id alone",
            "The MCP server opened the event stream of an existing session (an HTTP GET with Accept: "
                    + "text/event-stream and the session's Mcp-Session-Id) after every credential was removed, "
                    + "although it requires authentication elsewhere on this host: the last request in the evidence "
                    + "is a 401 challenge, protected-resource metadata or another request refused without "
                    + "credentials. Anyone who learns a session id can receive the notifications and requests the "
                    + "server sends to that session's client. The MCP specification says servers must not use "
                    + "sessions for authentication and must verify every inbound request.",
            FindingKind.AUTHENTICATE_THE_STREAM + " Accept a session's stream only from the principal that created "
                    + "the session.",
            List.of(new Cwe(287, "Improper Authentication")));

    private static final String ANONYMOUS_EXECUTION_NAME = "MCP request executed without authentication";
    private static final String REQUIRE_AUTHENTICATION = "Require authentication on every MCP endpoint and method, "
            + "including when the server is bound to a network interface, and reject requests without a valid "
            + "credential with HTTP 401.";

    private static final String AUTHENTICATE_THE_STREAM = "Authenticate the GET event stream from its own "
            + "credentials exactly as POST requests are authenticated, and reject a stream request without a valid "
            + "credential with HTTP 401 before opening the stream.";

    private final String issueName;
    private final String background;
    private final String remediation;
    private final List<Cwe> cwes;

    FindingKind(String issueName, String background, String remediation, List<Cwe> cwes) {
        this.issueName = issueName;
        this.background = background;
        this.remediation = remediation;
        this.cwes = cwes;
    }

    boolean concernsEventStream() {
        return this == ANONYMOUS_STREAM || this == SESSION_STREAM;
    }

    String issueName() {
        return issueName;
    }

    String background() {
        return background;
    }

    String remediation() {
        return remediation;
    }

    List<Cwe> cwes() {
        return cwes;
    }
}
