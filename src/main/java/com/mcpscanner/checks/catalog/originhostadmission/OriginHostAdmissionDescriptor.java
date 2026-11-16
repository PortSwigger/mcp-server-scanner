package com.mcpscanner.checks.catalog.originhostadmission;

import burp.api.montoya.scanner.audit.issues.AuditIssueConfidence;
import burp.api.montoya.scanner.audit.issues.AuditIssueSeverity;
import com.mcpscanner.checks.api.CheckDescriptor;
import com.mcpscanner.checks.api.CheckKind;
import com.mcpscanner.checks.issue.Cwe;

import java.util.List;

final class OriginHostAdmissionDescriptor {

    static final CheckDescriptor DESCRIPTOR = new CheckDescriptor(
            "origin-host-admission",
            "MCP Origin/Host admission",
            "Replays a captured read-only MCP request under hostile Origin and Host headers and reports when the "
                    + "server returns the same successful result, which is the precondition for DNS rebinding "
                    + "and cross-site requests against local MCP servers. On Streamable HTTP it also opens the "
                    + "GET event stream under hostile Origins beside a same-origin control, and reports when CORS lets a "
                    + "foreign origin read the replies (approved preflight and reply, or a legacy SSE stream).",
            CheckKind.HOST,
            AuditIssueSeverity.HIGH,
            AuditIssueConfidence.FIRM,
            true,
            List.of(
                    "https://modelcontextprotocol.io/specification/2025-11-25/basic/transports#security-warning",
                    "https://portswigger.net/web-security/cors"),
            "The MCP transport specification requires servers to validate the Origin header and recommends "
                    + "binding local servers to loopback. Accepting a foreign Origin or Host is a precondition for "
                    + "a web page in the user's browser to drive a local server through cross-site requests or DNS "
                    + "rebinding; whether a browser can actually deliver the request depends on CORS, TLS and how "
                    + "the server is reached.",
            List.of(new Cwe(346, "Origin Validation Error")));

    private OriginHostAdmissionDescriptor() {
    }
}
