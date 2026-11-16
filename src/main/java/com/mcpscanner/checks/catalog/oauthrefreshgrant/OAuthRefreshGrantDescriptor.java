package com.mcpscanner.checks.catalog.oauthrefreshgrant;

import burp.api.montoya.scanner.audit.issues.AuditIssueConfidence;
import burp.api.montoya.scanner.audit.issues.AuditIssueSeverity;
import com.mcpscanner.checks.api.CheckDescriptor;
import com.mcpscanner.checks.api.CheckKind;
import com.mcpscanner.checks.issue.Cwe;

import java.util.List;
import java.util.Optional;

final class OAuthRefreshGrantDescriptor {

    static final CheckDescriptor DESCRIPTOR = new CheckDescriptor(
            "oauth-refresh-grant",
            "MCP OAuth refresh grant validation",
            "Runs refresh_token grants on the extension's own OAuth session to test whether the authorization "
                    + "server authenticates confidential clients and refuses scope expansion. Rotated tokens are "
                    + "adopted into the live session.",
            CheckKind.HOST,
            AuditIssueSeverity.MEDIUM,
            AuditIssueConfidence.FIRM,
            true,
            List.of("https://www.rfc-editor.org/rfc/rfc6749#section-6",
                    "https://www.rfc-editor.org/rfc/rfc9700#section-4.14",
                    "https://modelcontextprotocol.io/specification/draft/basic/authorization"),
            Optional.empty(),
            "An OAuth refresh token lets a client obtain new access tokens without the resource owner. RFC 6749 "
                    + "section 6 requires the authorization server to authenticate confidential clients on the "
                    + "refresh_token grant and forbids granting any scope the resource owner did not originally "
                    + "grant. If either rule is not enforced, a leaked refresh token is worth more than it should be: "
                    + "it can be redeemed without the client's credentials, or traded for broader access.",
            List.of(new Cwe(287, "Improper Authentication"), new Cwe(285, "Improper Authorization")));

    private OAuthRefreshGrantDescriptor() {
    }
}
