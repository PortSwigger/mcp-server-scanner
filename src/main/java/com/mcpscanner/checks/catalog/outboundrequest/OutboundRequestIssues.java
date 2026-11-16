package com.mcpscanner.checks.catalog.outboundrequest;

import burp.api.montoya.collaborator.Interaction;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.scanner.audit.issues.AuditIssue;
import com.mcpscanner.checks.api.CheckDescriptor;
import com.mcpscanner.checks.issue.IssueBodyBuilder;
import com.mcpscanner.checks.issue.IssueMetadataRenderer;
import com.mcpscanner.checks.issue.IssueRating;
import com.mcpscanner.checks.shared.collaborator.InteractionDescription;
import com.mcpscanner.checks.shared.collaborator.ObservedInteractions;

import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

final class OutboundRequestIssues {

    private static final String FIELD_PREFIX = "Field: ";
    private static final String CONFIRMED_IN = "Confirmed in ";
    private static final String ENDPOINT_WIDE = ". This field means the same in every MCP method, so the scanner "
            + "reports it once for this endpoint and stops probing it in other methods once the server has made an "
            + "HTTP request to a probe host from it.";
    private static final String PROBE_METHOD = "The scanner placed a unique Burp Collaborator host in this field "
            + "only, in several forms (such as an absolute URL, a bare host or a command-line flag such as --server=), "
            + "each in its own request. When only a flag-shaped value makes the server connect, the field most likely "
            + "reaches a program's argument list, where it is parsed as an option. The Collaborator server then "
            + "received these interactions for the probes listed:";
    private static final String HTTP_PROVEN = "The Collaborator server received an HTTP request for a host that "
            + "appeared only in this field, so something that processed the probe made a request to it.";
    private static final String LOOKUP_ONLY = "The Collaborator server received only DNS lookups for the probe "
            + "host. A lookup can come from a validator that resolves a host and then refuses it, or from "
            + "infrastructure that inspects requests, so confirm that a request is actually made before relying "
            + "on this.";
    private static final String CREDENTIALS = "The outbound request carried credential headers, which were sent to "
            + "the host the scanner chose: ";

    private final CheckDescriptor descriptor;

    OutboundRequestIssues(CheckDescriptor descriptor) {
        this.descriptor = descriptor;
    }

    Optional<OutboundFinding> findingFor(ProbedField field, List<SentProbe> sent, ObservedInteractions observed,
                                  HttpRequestResponse base) {
        List<SentProbe> triggering = sent.stream().filter(probe -> !observed.of(probe.payload()).isEmpty()).toList();
        if (triggering.isEmpty()) {
            return Optional.empty();
        }
        InteractionEvidence evidence = new InteractionEvidence(triggering.stream()
                .flatMap(probe -> observed.of(probe.payload()).stream()).toList());
        List<String> credentials = evidence.forwardedCredentialHeaders();
        FieldCategory category = field.category().reported(!credentials.isEmpty());
        IssueRating rating = category.rating(evidence.strength(), !credentials.isEmpty());
        return Optional.of(new OutboundFinding(AuditIssue.auditIssue(category.issueName(),
                detail(field, category, triggering, observed, evidence, credentials), category.remediation(),
                base.request().url(), rating.severity(), rating.confidence(),
                IssueMetadataRenderer.background(descriptor.issueBackground(), descriptor.cwes(),
                        descriptor.references()),
                null, rating.severity(), exchanges(triggering)), evidence.strength()));
    }

    private static String detail(ProbedField field, FieldCategory category, List<SentProbe> triggering,
                                 ObservedInteractions observed,
                                 InteractionEvidence evidence, List<String> credentials) {
        IssueBodyBuilder body = new IssueBodyBuilder().paragraph(FIELD_PREFIX + field.subject());
        if (field.operation().isEmpty()) {
            body.paragraph(CONFIRMED_IN + field.request() + ENDPOINT_WIDE);
        }
        body.paragraph(PROBE_METHOD)
                .findings(triggering.stream().flatMap(probe -> observed.of(probe.payload()).stream()
                        .map(interaction -> describe(probe, interaction))).toList())
                .paragraph(evidence.strength() == InteractionStrength.HTTP_REQUEST ? HTTP_PROVEN : LOOKUP_ONLY);
        if (!credentials.isEmpty()) {
            body.paragraph(CREDENTIALS + String.join(", ", credentials) + ".");
        }
        return body.paragraph(category.scope()).build();
    }

    private static String describe(SentProbe probe, Interaction interaction) {
        return probe.form().label() + " " + probe.value() + ": " + InteractionDescription.of(interaction);
    }

    private static List<HttpRequestResponse> exchanges(List<SentProbe> triggering) {
        return new ArrayList<>(triggering.stream().map(SentProbe::exchange).toList());
    }
}
