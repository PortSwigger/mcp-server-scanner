package com.mcpscanner.checks.content;

import burp.api.montoya.http.HttpService;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.scanner.audit.issues.AuditIssue;
import burp.api.montoya.scanner.audit.issues.AuditIssueSeverity;
import com.mcpscanner.checks.issue.IssueBodyBuilder;
import com.mcpscanner.checks.issue.IssueMetadata;
import com.mcpscanner.checks.issue.IssueMetadataRenderer;
import com.mcpscanner.mcp.McpRequestDetector;

import java.util.ArrayList;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Builds {@link AuditIssue}s from grouped {@link ContentFinding}s. Used by both the
 * connect-time {@link DiscoveryContentScanner} and the passive
 * {@code JsonRpcDiscoveryResponseScanner} so the issue shape (name / detail / severity /
 * background / remediation) stays identical regardless of which path emitted the finding.
 *
 * <p>Background, remediation, CWE classifications, and references all come from the rule's own
 * {@link ContentRule#metadata()} — so an icon finding gets icon guidance, not credential
 * rotation guidance. The rotation/principle in a credential or info-disclosure remediation is
 * location-agnostic; {@link SourceContext} carries the surface-specific clause (where to remove
 * the value) that is appended only when {@link IssueMetadata#surfaceSpecificRemediation()} is set,
 * so an icon finding (already self-contained, discovery-only) is left untouched.
 */
public final class ContentFindingIssueBuilder {

    private static final int MATCH_DETAIL_LIMIT = 80;
    private static final Comparator<ContentFinding> BY_SEVERITY =
            Comparator.comparingInt(f -> -f.severity().ordinal());

    public static final SourceContext DISCOVERY_SOURCE = new SourceContext(
            "MCP discovery", " in MCP discovery",
            "Remove it from the MCP discovery metadata (tool/resource/prompt descriptions, schemas, "
                    + "server info).");

    public static final SourceContext RESPONSE_SOURCE = new SourceContext(
            "MCP responses", " in MCP responses",
            "Ensure the tool/resource/prompt handler does not return secrets or PII in its output; "
                    + "strip or redact sensitive values before returning them.");

    public record SourceContext(String detailPhrase, String nameQualifier, String remediationClause) {}

    private ContentFindingIssueBuilder() {}

    public static List<AuditIssue> buildAll(List<ContentFinding> findings,
                                            HttpService host,
                                            HttpRequestResponse evidence) {
        return buildAll(findings, host, evidence, DISCOVERY_SOURCE);
    }

    public static List<AuditIssue> buildAll(List<ContentFinding> findings,
                                            HttpService host,
                                            HttpRequestResponse evidence,
                                            SourceContext sourceContext) {
        Map<ContentRule, List<ContentFinding>> grouped = groupByRule(findings);
        List<AuditIssue> issues = new ArrayList<>(grouped.size());
        for (Map.Entry<ContentRule, List<ContentFinding>> entry : grouped.entrySet()) {
            issues.add(buildIssue(entry.getKey(), entry.getValue(), host, evidence, sourceContext));
        }
        return issues;
    }

    private static Map<ContentRule, List<ContentFinding>> groupByRule(List<ContentFinding> findings) {
        Map<ContentRule, List<ContentFinding>> grouped = new LinkedHashMap<>();
        for (ContentFinding finding : findings) {
            grouped.computeIfAbsent(finding.rule(), r -> new ArrayList<>()).add(finding);
        }
        return grouped;
    }

    private static AuditIssue buildIssue(ContentRule rule,
                                         List<ContentFinding> findings,
                                         HttpService host,
                                         HttpRequestResponse evidence,
                                         SourceContext sourceContext) {
        String baseUrl = McpRequestDetector.baseUrl(host);
        AuditIssueSeverity severity = highestSeverity(findings, rule.severity());
        IssueMetadata metadata = rule.metadata();
        return AuditIssue.auditIssue(
                rule.displayName() + sourceContext.nameQualifier(),
                renderDetail(rule, findings, baseUrl, sourceContext),
                renderRemediation(metadata, sourceContext),
                baseUrl,
                severity,
                rule.confidence(),
                IssueMetadataRenderer.background(metadata),
                null, severity,
                evidence != null ? List.of(evidence) : List.of()
        );
    }

    private static AuditIssueSeverity highestSeverity(List<ContentFinding> findings,
                                                      AuditIssueSeverity fallback) {
        return findings.stream()
                .max(BY_SEVERITY)
                .map(ContentFinding::severity)
                .orElse(fallback);
    }

    private static String renderDetail(ContentRule rule, List<ContentFinding> findings, String baseUrl,
                                       SourceContext sourceContext) {
        int count = findings.size();
        return new IssueBodyBuilder()
                .paragraph("Found " + count + " " + rule.displayName()
                        + (count == 1 ? " finding" : " findings")
                        + " in " + sourceContext.detailPhrase() + " for " + baseUrl + ".")
                .findings(renderFindingItems(findings))
                .build();
    }

    private static List<String> renderFindingItems(List<ContentFinding> findings) {
        List<String> items = new ArrayList<>(findings.size());
        for (ContentFinding finding : findings) {
            InspectedField field = finding.field();
            items.add(field.objectType() + " \"" + field.objectName() + "\"."
                    + field.fieldPath() + " -> " + truncate(finding.matchedText()));
        }
        return items;
    }

    private static String truncate(String value) {
        if (value == null) {
            return "";
        }
        if (value.length() <= MATCH_DETAIL_LIMIT) {
            return value;
        }
        return value.substring(0, MATCH_DETAIL_LIMIT) + "...";
    }

    private static String renderRemediation(IssueMetadata metadata, SourceContext sourceContext) {
        IssueBodyBuilder builder = new IssueBodyBuilder().paragraph(metadata.remediation());
        if (metadata.surfaceSpecificRemediation()) {
            builder.paragraph(sourceContext.remediationClause());
        }
        return builder.build();
    }
}
