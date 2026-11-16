package com.mcpscanner.checks.catalog.oauthconsentstructurereflection;

import burp.api.montoya.scanner.audit.issues.AuditIssueConfidence;
import burp.api.montoya.scanner.audit.issues.AuditIssueSeverity;
import com.mcpscanner.checks.api.CheckDescriptor;
import com.mcpscanner.checks.api.CheckKind;
import com.mcpscanner.checks.issue.Cwe;

import java.util.List;

final class OAuthConsentStructureDescriptor {

    static final CheckDescriptor DESCRIPTOR = new CheckDescriptor(
            "oauth-consent-structure-reflection",
            "MCP OAuth consent page HTML structure reflection",
            "Registers an OAuth client whose client_name carries an inert HTML marker, sends an authorization "
                    + "request whose state carries another, and reports a marker that an HTML parser finds as an "
                    + "element or attribute on the authorization page but not on an unregistered-client control. "
                    + "Reports the page's Content-Security-Policy script restrictions without claiming script "
                    + "execution.",
            CheckKind.HOST,
            AuditIssueSeverity.INFORMATION,
            AuditIssueConfidence.TENTATIVE,
            true,
            List.of(
                    "https://modelcontextprotocol.io/specification/2025-11-25/basic/authorization",
                    "https://datatracker.ietf.org/doc/html/rfc7591#section-2",
                    "https://datatracker.ietf.org/doc/html/rfc6749#section-4.1.1",
                    "https://www.w3.org/TR/CSP3/"),
            "OAuth authorization servers that support dynamic client registration let anyone choose a client's "
                    + "display metadata, and the authorization request's state is chosen by whoever builds the "
                    + "link. A consent or authorization page that writes either value without encoding lets an "
                    + "attacker change the page's markup. Whether that leads to script execution depends on the "
                    + "exact context, browser parsing and the page's Content-Security-Policy.",
            List.of(new Cwe(116, "Improper Encoding or Escaping of Output")));

    private OAuthConsentStructureDescriptor() {
    }
}
