package com.mcpscanner.checks.catalog.outboundrequest;

import burp.api.montoya.scanner.audit.issues.AuditIssueConfidence;
import burp.api.montoya.scanner.audit.issues.AuditIssueSeverity;
import com.mcpscanner.checks.api.CheckDescriptor;
import com.mcpscanner.checks.api.CheckKind;
import com.mcpscanner.checks.issue.Cwe;

import java.util.List;

final class OutboundRequestDescriptor {

    static final CheckDescriptor DESCRIPTOR = new CheckDescriptor(
            "outbound-request",
            "MCP outbound request",
            "Places a unique Burp Collaborator host, as an absolute URL, as a bare host, in command-line flag shapes "
                    + "and, in a URL value, after the value's own host (to pass prefix allowlists), in every MCP request "
                    + "field and header one at a time, and in the URL fields of OAuth client registration and "
                    + "authorization requests, then reports when the server resolves or requests that host.",
            CheckKind.INSERTION_POINT,
            AuditIssueSeverity.MEDIUM,
            AuditIssueConfidence.FIRM,
            true,
            List.of(
                    "https://modelcontextprotocol.io/specification/2025-11-25/basic/security_best_practices",
                    "https://portswigger.net/burp/application-security-testing/oast",
                    "https://portswigger.net/burp/documentation/collaborator",
                    "https://www.rfc-editor.org/rfc/rfc7591#section-5"),
            "Some MCP tools request caller-supplied URLs by design, such as fetch, browse or scrape tools. A field "
                    + "or header with any other purpose that chooses the host the server connects to lets a caller "
                    + "direct the server's requests, and if credentials are attached they go to that host. Whether "
                    + "internal services or cloud metadata endpoints are reachable depends on the server's egress, "
                    + "which this check does not test. The scanner detects the outbound connection out of band "
                    + "through Burp Collaborator.",
            List.of(new Cwe(441, "Unintended Proxy or Intermediary ('Confused Deputy')")));

    private OutboundRequestDescriptor() {
    }
}
