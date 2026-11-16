package com.mcpscanner.checks.catalog.originhostadmission;

import burp.api.montoya.scanner.audit.issues.AuditIssue;
import burp.api.montoya.scanner.audit.issues.AuditIssueConfidence;
import burp.api.montoya.scanner.audit.issues.AuditIssueSeverity;
import com.mcpscanner.checks.api.CheckDescriptor;
import com.mcpscanner.checks.issue.IssueBodyBuilder;
import com.mcpscanner.checks.issue.IssueMetadataRenderer;
import com.mcpscanner.checks.shared.stream.StreamEvidenceNote;

import java.util.Map;
import java.util.Optional;

final class CorsIssues {

    static final String ISSUE_NAME = "MCP cross-origin read allowed by CORS";

    private static final String LEAD = "The MCP server's CORS headers let a page on the foreign origin "
            + CorsProbe.FOREIGN_ORIGIN + " read its replies:";
    private static final Map<CorsAuth, String> AUTH_NOTES = Map.of(
            CorsAuth.NONE, "The requests carried no credentials, so any web page the user visits can make "
                    + "them and read the replies, including from a server on loopback or a private network.",
            CorsAuth.HEADER, "The requests carried a credential header such as a bearer token, which a "
                    + "cross-site page cannot attach. Confirm whether the endpoint answers without credentials "
                    + "before treating this as exploitable.",
            CorsAuth.COOKIE, "The requests carried cookies. A browser attaches them to a cross-origin request "
                    + "only when the server echoes the exact origin and sends " + CorsGrant.ALLOW_CREDENTIALS
                    + ": true on both the preflight and the reply.");
    private static final String CREDENTIALED_APPROVAL = "The server echoed the exact origin with "
            + CorsGrant.ALLOW_CREDENTIALS + ": true, so a page can read the replies with the user's cookies.";
    private static final String REMEDIATION = "Do not send Access-Control-Allow-Origin for MCP endpoints, or "
            + "send it only for an explicit allowlist of trusted origins; never reflect the request's Origin or "
            + "use * together with credentials. Validate the Origin header on every MCP request and require "
            + "authentication.";

    private final CheckDescriptor descriptor;

    CorsIssues(CheckDescriptor descriptor) {
        this.descriptor = descriptor;
    }

    AuditIssue issueFor(CorsFinding finding) {
        AuditIssueSeverity severity = finding.severity();
        return AuditIssue.auditIssue(ISSUE_NAME, detail(finding), REMEDIATION, finding.url(), severity,
                AuditIssueConfidence.FIRM,
                IssueMetadataRenderer.background(descriptor.issueBackground(), descriptor.cwes(),
                        descriptor.references()),
                null, severity, finding.evidence().stream().map(CorsEvidence::exchange).toList());
    }

    private static String detail(CorsFinding finding) {
        IssueBodyBuilder body = new IssueBodyBuilder()
                .paragraph(LEAD)
                .findings(finding.evidence().stream().map(CorsEvidence::grantSummary).toList())
                .paragraph(finding.scope());
        outsideBurpNote(finding).ifPresent(body::paragraph);
        body.paragraph(AUTH_NOTES.get(finding.auth()));
        if (finding.approvedWithCredentials()) {
            body.paragraph(CREDENTIALED_APPROVAL);
        }
        return body.build();
    }

    private static Optional<String> outsideBurpNote(CorsFinding finding) {
        return StreamEvidenceNote.sentOutsideBurp(finding.evidence().stream()
                .filter(CorsEvidence::outsideBurp).map(CorsEvidence::name).toList(), finding.evidence().size());
    }
}
