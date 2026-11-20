package com.mcpscanner.checks.catalog.downstreamrouteescape;

import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.scanner.audit.insertionpoint.AuditInsertionPoint;
import burp.api.montoya.scanner.audit.issues.AuditIssue;
import com.mcpscanner.checks.api.CheckDescriptor;
import com.mcpscanner.checks.shared.evidence.PayloadHighlights;
import com.mcpscanner.checks.issue.IssueBodyBuilder;
import com.mcpscanner.checks.issue.IssueMetadataRenderer;

import java.util.ArrayList;
import java.util.List;
import java.util.stream.Collectors;

final class DownstreamRouteEscapeIssues {

    private static final String EVIDENCE_SCOPE = "This suggests that the server resolves dot segments in this value "
            + "as part of a path: typically the route of a downstream API request, but a file path behaves the same "
            + "way. It does not show which route or file was reached, that it is protected, or that any operation "
            + "was performed.";
    private static final String FOLLOW_UP = "Follow up by finding the component that consumes this value, then "
            + "check whether a traversal value plus a sibling route segment returns data or performs actions the "
            + "tool is not meant to expose with the server's own downstream credentials.";
    private static final String REMEDIATION = "Encode every caller-supplied value as a single path segment before "
            + "building a downstream URL, reject '.' and '..' segments after decoding, and verify that the "
            + "resolved URL still lies under the route prefix configured for the tool.";

    private final CheckDescriptor descriptor;

    DownstreamRouteEscapeIssues(CheckDescriptor descriptor) {
        this.descriptor = descriptor;
    }

    AuditIssue issueFor(HttpRequestResponse base, AuditInsertionPoint insertionPoint, RouteDifference difference) {
        return AuditIssue.auditIssue(descriptor.issueName(), detail(base, insertionPoint, difference),
                REMEDIATION,
                base.request().url(), descriptor.headlineSeverity(), descriptor.headlineConfidence(),
                IssueMetadataRenderer.background(descriptor.issueBackground(), descriptor.cwes(),
                        descriptor.references()),
                null, descriptor.headlineSeverity(), evidence(base, insertionPoint, difference));
    }

    private static String detail(HttpRequestResponse base, AuditInsertionPoint insertionPoint,
                                 RouteDifference difference) {
        RouteProbe probe = difference.probe();
        return new IssueBodyBuilder()
                .paragraph("Request: " + CallSubject.of(base.request().bodyToString()))
                .paragraph("Insertion point: " + insertionPoint.name())
                .paragraph("The path traversal values " + quoted(probe.traversals()) + " returned the same "
                        + "successful result each time, and again when " + quoted(first(probe.traversals()))
                        + " was repeated. That result differed from the result for the matched non-traversal values "
                        + quoted(probe.controls()) + ", which agreed with each other and again when "
                        + quoted(first(probe.controls())) + " was repeated.")
                .paragraph(attachedValues(probe))
                .paragraph(EVIDENCE_SCOPE)
                .paragraph(FOLLOW_UP)
                .build();
    }

    private static String attachedValues(RouteProbe probe) {
        String contrasts = probe.contrasts().isEmpty() ? ""
                : ", and the current-segment value " + quoted(probe.contrasts()) + " whose result also differed";
        return "The attached requests show the traversal value " + quoted(first(probe.traversals()))
                + " and the non-traversal value " + quoted(first(probe.controls())) + contrasts + ".";
    }

    private static List<String> first(List<String> values) {
        return values.subList(0, 1);
    }

    private static String quoted(List<String> values) {
        return values.stream().distinct().map(value -> "\"" + value + "\"").collect(Collectors.joining(", "));
    }

    private static List<HttpRequestResponse> evidence(HttpRequestResponse base, AuditInsertionPoint insertionPoint,
                                                      RouteDifference difference) {
        List<HttpRequestResponse> evidence = new ArrayList<>();
        evidence.add(base);
        difference.evidence().forEach(sent ->
                evidence.add(PayloadHighlights.ofPayload(sent.exchange(), insertionPoint, sent.value())));
        return evidence;
    }
}
