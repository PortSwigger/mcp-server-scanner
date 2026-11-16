package com.mcpscanner.checks.catalog.sessionlifecycle;

import burp.api.montoya.scanner.audit.issues.AuditIssueConfidence;
import burp.api.montoya.scanner.audit.issues.AuditIssueSeverity;
import com.mcpscanner.checks.api.CheckDescriptor;
import com.mcpscanner.checks.api.CheckKind;
import com.mcpscanner.checks.issue.Cwe;

import java.util.List;

final class SessionLifecycleDescriptor {

    static final CheckDescriptor DESCRIPTOR = new CheckDescriptor(
            "session-lifecycle",
            "MCP session lifecycle",
            "When the server issues an Mcp-Session-Id, opens eight separate probe sessions (never the "
                    + "scanner's own; up to 30 when the first eight are borderline) and judges whether their IDs are "
                    + "guessable: repeated, increasing, a known time-based format (version 1, 6 or 7 UUID, ULID, "
                    + "KSUID, Snowflake, MongoDB ObjectId) whose clock and counter fields leave too little "
                    + "randomness, or too few varying bits once hex or base64 is decoded. A guessable ID that answers a request without credentials is "
                    + "rated High. One probe session is then closed with DELETE, pinged again and asked for its GET "
                    + "event stream; an answer or an opened stream after a successful DELETE is reported (a stream "
                    + "only when a never-issued ID's stream is refused). Every probe session is closed and the live session is pinged "
                    + "afterwards. On legacy SSE servers only the guessability test runs, on probe streams of its "
                    + "own.",
            CheckKind.HOST,
            AuditIssueSeverity.LOW,
            AuditIssueConfidence.FIRM,
            true,
            List.of(
                    "https://modelcontextprotocol.io/specification/2025-11-25/basic/transports#session-management",
                    "https://modelcontextprotocol.io/specification/2025-11-25/basic/security_best_practices#session-hijacking"),
            "An MCP session ID identifies a client's session on a stateful server. If IDs can be predicted, an "
                    + "attacker can address another client's session; if the server treats the ID as a credential, "
                    + "that is enough to act as the other client. A session that survives an explicit DELETE stays "
                    + "usable by anyone who saw its ID after the client believed it was gone.",
            List.of(new Cwe(330, "Use of Insufficiently Random Values"),
                    new Cwe(613, "Insufficient Session Expiration")));

    private SessionLifecycleDescriptor() {
    }
}
