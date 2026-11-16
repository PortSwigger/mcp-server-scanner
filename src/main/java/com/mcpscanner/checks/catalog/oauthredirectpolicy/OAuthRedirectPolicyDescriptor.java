package com.mcpscanner.checks.catalog.oauthredirectpolicy;

import burp.api.montoya.scanner.audit.issues.AuditIssueConfidence;
import burp.api.montoya.scanner.audit.issues.AuditIssueSeverity;
import com.mcpscanner.checks.api.CheckDescriptor;
import com.mcpscanner.checks.api.CheckKind;
import com.mcpscanner.checks.issue.Cwe;

import java.net.URI;
import java.util.List;

final class OAuthRedirectPolicyDescriptor {

    static final CheckDescriptor DESCRIPTOR = new CheckDescriptor(
            "oauth-redirect-policy",
            "MCP OAuth redirect policy",
            "Registers the scanner's own OAuth clients through anonymous dynamic client registration and tests "
                    + "whether the authorization server sends codes or errors to redirect URIs those clients "
                    + "never registered (unregistered path, http downgrade, dot-segment path, expanded wildcard "
                    + "host, unsupported response_type, denied consent form), and whether registration accepts "
                    + "javascript: or data: redirect URIs. Authorization requests carry the MCP session's cookies "
                    + "only when the authorization endpoint shares the MCP origin. The check never redeems a code "
                    + "and never uses the extension's own OAuth client. It deletes its registered probe clients "
                    + "through RFC 7592 client management when the authorization server offers it, and stops "
                    + "probing, cleanup included, when the server answers HTTP 429.",
            CheckKind.HOST,
            AuditIssueSeverity.MEDIUM,
            AuditIssueConfidence.FIRM,
            true,
            List.of(
                    "https://modelcontextprotocol.io/specification/2025-11-25/basic/authorization",
                    "https://datatracker.ietf.org/doc/html/rfc9700#section-2.1",
                    "https://datatracker.ietf.org/doc/html/rfc7591#section-2"),
            "An OAuth authorization server must send authorization responses only to a redirect URI registered "
                    + "for the requesting client, compared by exact string match. When it does not, an attacker "
                    + "can steer a victim's authorization code or error to a URI the client never registered.",
            List.of(new Cwe(601, "URL Redirection to Untrusted Site ('Open Redirect')"),
                    new Cwe(20, "Improper Input Validation")));

    private OAuthRedirectPolicyDescriptor() {
    }
}
