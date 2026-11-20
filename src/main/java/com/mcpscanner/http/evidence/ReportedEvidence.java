package com.mcpscanner.http.evidence;

import burp.api.montoya.http.message.HttpHeader;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.api.montoya.scanner.audit.issues.AuditIssue;
import burp.api.montoya.scanner.audit.issues.AuditIssueDefinition;
import com.mcpscanner.http.TextMarkers;

import java.util.List;
import java.util.Objects;
import java.util.Set;

public final class ReportedEvidence {

    private final Set<String> sentinelHeaders;
    private final SentinelFreeResponse sentinelFreeResponse;

    public ReportedEvidence(Set<String> sentinelHeaders) {
        this.sentinelHeaders = Objects.requireNonNull(sentinelHeaders, "sentinelHeaders must not be null");
        this.sentinelFreeResponse = new SentinelFreeResponse(sentinelHeaders);
    }

    public List<AuditIssue> of(List<AuditIssue> issues) {
        return issues.stream().map(this::of).toList();
    }

    public AuditIssue of(AuditIssue issue) {
        List<HttpRequestResponse> evidence = issue.requestResponses();
        List<HttpRequestResponse> cleaned = evidence.stream().map(this::sentinelFree).toList();
        String detail = withTruncationSentence(issue.detail(), cleaned);
        return sameItems(evidence, cleaned) && Objects.equals(detail, issue.detail())
                ? issue : rebuilt(issue, detail, cleaned);
    }

    private HttpRequestResponse sentinelFree(HttpRequestResponse item) {
        if (item == null) {
            return null;
        }
        HttpRequest request = item.request();
        HttpResponse response = item.response();
        HttpRequest cleanRequest = request == null ? null : withoutSentinels(request);
        HttpResponse cleanResponse = response == null ? null : sentinelFreeResponse.of(response);
        if (cleanRequest == request && cleanResponse == response) {
            return item;
        }
        return TextMarkers.carriedOver(item,
                HttpRequestResponse.httpRequestResponse(cleanRequest, cleanResponse, item.annotations()));
    }

    private HttpRequest withoutSentinels(HttpRequest request) {
        List<HttpHeader> sentinels = request.headers().stream()
                .filter(header -> sentinelHeaders.contains(header.name())).toList();
        return sentinels.isEmpty() ? request : request.withRemovedHeaders(sentinels);
    }

    private static String withTruncationSentence(String detail, List<HttpRequestResponse> evidence) {
        String current = Objects.requireNonNullElse(detail, "");
        boolean unsaid = evidence.stream().anyMatch(TruncationNote::on)
                && !current.contains(TruncationNote.DETAIL_SENTENCE);
        return unsaid ? current + TruncationNote.DETAIL_SENTENCE : detail;
    }

    private static boolean sameItems(List<HttpRequestResponse> before, List<HttpRequestResponse> after) {
        for (int index = 0; index < before.size(); index++) {
            if (before.get(index) != after.get(index)) {
                return false;
            }
        }
        return true;
    }

    private static AuditIssue rebuilt(AuditIssue issue, String detail, List<HttpRequestResponse> evidence) {
        AuditIssueDefinition definition = issue.definition();
        return AuditIssue.auditIssue(issue.name(), detail, issue.remediation(), issue.baseUrl(),
                issue.severity(), issue.confidence(), definition.background(), definition.remediation(),
                definition.typicalSeverity(), evidence.stream().filter(Objects::nonNull).toList());
    }
}
