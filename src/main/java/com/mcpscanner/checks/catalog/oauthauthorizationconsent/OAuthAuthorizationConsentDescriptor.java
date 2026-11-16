package com.mcpscanner.checks.catalog.oauthauthorizationconsent;

import burp.api.montoya.scanner.audit.issues.AuditIssueConfidence;
import burp.api.montoya.scanner.audit.issues.AuditIssueSeverity;
import com.mcpscanner.checks.api.CheckDescriptor;
import com.mcpscanner.checks.api.CheckKind;
import com.mcpscanner.checks.issue.Cwe;

import java.util.List;

final class OAuthAuthorizationConsentDescriptor {

    static final CheckDescriptor DESCRIPTOR = new CheckDescriptor(
            "oauth-authorization-consent",
            "MCP OAuth authorization without login or consent",
            "Registers a throwaway public OAuth client through anonymous dynamic client registration and "
                    + "requests an authorization code with no user session, following at most five same-origin "
                    + "redirects with only the cookies they set and never another origin. A code delivered to the "
                    + "probe client's callback is redeemed with PKCE, and the token is tried on tools/list in a "
                    + "fresh MCP session, beside an anonymous control in its own fresh session. When the token "
                    + "turns the refused request into a success, the check redeems the same code again, then a "
                    + "fresh code five times concurrently, and reports a second working token. A code issued only "
                    + "after the server created a session for the anonymous visitor is reported as tentative. "
                    + "The check never sends the scanner's own credentials to the authorization server, revokes "
                    + "every token it obtained through RFC 7009 when the server offers it (logging an error "
                    + "otherwise), and deletes its probe client through RFC 7592 client management when offered.",
            CheckKind.HOST,
            AuditIssueSeverity.HIGH,
            AuditIssueConfidence.FIRM,
            true,
            List.of(
                    "https://modelcontextprotocol.io/specification/2025-11-25/basic/security_best_practices",
                    "https://datatracker.ietf.org/doc/html/rfc6749#section-4.1.2",
                    "https://datatracker.ietf.org/doc/html/rfc9700#section-4.2"),
            "An MCP server's authorization endpoint must authenticate the user and obtain their consent before it "
                    + "issues an authorization code, and an authorization code must be redeemable only once. "
                    + "When it issues codes to anyone, any client that can reach it obtains the user's access, and "
                    + "a code redeemed twice yields tokens to whoever replays it.",
            List.of(new Cwe(306, "Missing Authentication for Critical Function"),
                    new Cwe(862, "Missing Authorization"),
                    new Cwe(367, "Time-of-check Time-of-use (TOCTOU) Race Condition")));

    private OAuthAuthorizationConsentDescriptor() {
    }
}
