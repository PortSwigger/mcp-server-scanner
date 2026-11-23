package com.mcpscanner.checks.catalog.oauthconsentstructurereflection;

import burp.api.montoya.scanner.audit.issues.AuditIssue;
import com.mcpscanner.checks.api.CheckDescriptor;
import com.mcpscanner.checks.issue.IssueBodyBuilder;
import com.mcpscanner.checks.issue.IssueMetadataRenderer;
import com.mcpscanner.checks.shared.oauth.HttpUris;

import java.util.List;

final class OAuthConsentStructureIssues {

    private final CheckDescriptor descriptor;

    OAuthConsentStructureIssues(CheckDescriptor descriptor) {
        this.descriptor = descriptor;
    }

    List<AuditIssue> issuesFor(ConsentStructureEvidence evidence) {
        return evidence.reflections().stream().map(reflection -> issue(reflection, evidence)).toList();
    }

    private AuditIssue issue(FieldReflection reflection, ConsentStructureEvidence evidence) {
        return AuditIssue.auditIssue(
                reflection.field().issueName(),
                detail(reflection, evidence),
                remediation(),
                HttpUris.withoutQuery(evidence.page().url()),
                descriptor.headlineSeverity(),
                descriptor.headlineConfidence(),
                IssueMetadataRenderer.background(descriptor.issueBackground(), descriptor.cwes(),
                        descriptor.references()),
                null,
                descriptor.headlineSeverity(),
                ConsentStructureExchanges.of(reflection, evidence));
    }

    private static String detail(FieldReflection reflection, ConsentStructureEvidence evidence) {
        StructureMarker marker = reflection.marker();
        return new IssueBodyBuilder()
                .paragraph("The authorization server placed " + reflection.field().origin() + " into the page at "
                        + evidence.page().url() + " without encoding it for its HTML context. The scanner sent an "
                        + "inert marker, " + marker.payload() + ", and an HTML parser found it on the page as "
                        + reflection.placement().parsedAs() + " (" + reflection.parsedName()
                        + ") outside script, comment, raw-text and inert containers.")
                .paragraph(provenance(reflection.field(), evidence))
                .paragraph("This shows that markup can be injected into the page. It does not show that script "
                        + "runs: no script was sent, no browser rendered the page and no consent was given.")
                .paragraph(evidence.scriptExecution().summary())
                .build();
    }

    private static String provenance(ReflectedField field, ConsentStructureEvidence evidence) {
        String control = evidence.client().clientId() + ConsentStructureProbe.CONTROL_CLIENT_SUFFIX;
        return switch (field) {
            case CLIENT_NAME -> "The marker was sent only in the registered client's metadata, never in the "
                    + "authorization request, so the structure came from the stored client_name.";
            case STATE -> "The same authorization request with the unregistered client_id " + control
                    + " did not produce that structure, so it is tied to the registered client's page rather than "
                    + "a generic error page that echoes the request.";
        };
    }

    private static String remediation() {
        return new IssueBodyBuilder()
                .paragraph("Encode client metadata and authorization request parameters for the exact HTML "
                        + "context they are written into, or render them with a templating engine that "
                        + "auto-escapes. Treat every dynamically registered client field as untrusted input.")
                .paragraph("Serve consent and authorization pages with a Content-Security-Policy whose "
                        + "script-src blocks inline script, as defence in depth.")
                .build();
    }
}
