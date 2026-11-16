package com.mcpscanner.checks.registry;

import burp.api.montoya.http.message.HttpHeader;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.api.montoya.scanner.audit.issues.AuditIssue;
import burp.api.montoya.scanner.audit.issues.AuditIssueDefinition;
import com.mcpscanner.checks.api.CheckLog;
import com.mcpscanner.http.TextMarkers;
import com.mcpscanner.mcp.ScannerSentinels;

import java.util.List;
import java.util.Objects;

final class SentinelFreeEvidence {

    private SentinelFreeEvidence() {
    }

    static void noteStillProxied(List<AuditIssue> issues, CheckLog log) {
        long stillProxied = issues.stream().flatMap(issue -> issue.requestResponses().stream())
                .filter(item -> item != null && item.response() != null)
                .filter(item -> item.response().hasHeader(ScannerSentinels.EXCHANGE_HEADER)).count();
        if (stillProxied > 0) {
            log.warn("issue evidence still shows the proxy hop for " + stillProxied
                    + " exchange(s): the upstream exchange was no longer stored, so the sentinel was stripped as a backstop");
        }
    }

    static List<AuditIssue> of(List<AuditIssue> issues) {
        return issues.stream().map(SentinelFreeEvidence::of).toList();
    }

    static AuditIssue of(AuditIssue issue) {
        List<HttpRequestResponse> evidence = issue.requestResponses();
        List<HttpRequestResponse> cleaned = evidence.stream().map(SentinelFreeEvidence::of).toList();
        return sameItems(evidence, cleaned) ? issue : rebuilt(issue, cleaned);
    }

    private static HttpRequestResponse of(HttpRequestResponse item) {
        if (item == null) {
            return null;
        }
        HttpRequest request = item.request();
        HttpResponse response = item.response();
        HttpRequest cleanRequest = request == null ? null : withoutSentinels(request);
        HttpResponse cleanResponse = response == null ? null : SentinelFreeResponse.of(response);
        if (cleanRequest == request && cleanResponse == response) {
            return item;
        }
        return TextMarkers.carriedOver(item, HttpRequestResponse.httpRequestResponse(cleanRequest, cleanResponse));
    }

    private static HttpRequest withoutSentinels(HttpRequest request) {
        List<HttpHeader> sentinels = request.headers().stream()
                .filter(header -> ScannerSentinels.ALL.contains(header.name())).toList();
        return sentinels.isEmpty() ? request : request.withRemovedHeaders(sentinels);
    }

    private static boolean sameItems(List<HttpRequestResponse> before, List<HttpRequestResponse> after) {
        for (int index = 0; index < before.size(); index++) {
            if (before.get(index) != after.get(index)) {
                return false;
            }
        }
        return true;
    }

    private static AuditIssue rebuilt(AuditIssue issue, List<HttpRequestResponse> evidence) {
        AuditIssueDefinition definition = issue.definition();
        return AuditIssue.auditIssue(issue.name(), issue.detail(), issue.remediation(), issue.baseUrl(),
                issue.severity(), issue.confidence(), definition.background(), definition.remediation(),
                definition.typicalSeverity(), evidence.stream().filter(Objects::nonNull).toList());
    }
}
