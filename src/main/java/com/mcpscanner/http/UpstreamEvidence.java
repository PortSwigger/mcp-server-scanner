package com.mcpscanner.http;

import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.scanner.audit.issues.AuditIssue;
import burp.api.montoya.scanner.audit.issues.AuditIssueDefinition;

import java.util.List;
import java.util.Objects;
import java.util.Optional;

public final class UpstreamEvidence {

    private final UpstreamExchanges exchanges;

    public UpstreamEvidence(UpstreamExchanges exchanges) {
        this.exchanges = Objects.requireNonNull(exchanges, "exchanges must not be null");
    }

    public ExchangeLease retaining() {
        return exchanges.retaining();
    }

    public List<AuditIssue> translate(List<AuditIssue> issues) {
        return issues.stream().map(this::translate).toList();
    }

    public AuditIssue translate(AuditIssue issue) {
        List<EvidenceSwap> swaps = issue.requestResponses().stream().map(this::swap).toList();
        Optional<EvidenceSwap> first = swaps.stream().filter(EvidenceSwap::swapped).findFirst();
        String url = exchanges.issueUrl(first.map(swap -> swap.rebasedUrl(issue.baseUrl())).orElse(issue.baseUrl()));
        return first.isEmpty() && Objects.equals(url, issue.baseUrl()) ? issue : rebuilt(issue, url, swaps);
    }

    private EvidenceSwap swap(HttpRequestResponse proxied) {
        return new EvidenceSwap(proxied, exchanges.upstreamOf(proxied)
                .map(upstream -> TextMarkers.carriedOver(proxied, unmarked(upstream))));
    }

    private static HttpRequestResponse unmarked(HttpRequestResponse upstream) {
        return HttpRequestResponse.httpRequestResponse(upstream.request(), upstream.response());
    }

    private static AuditIssue rebuilt(AuditIssue issue, String url, List<EvidenceSwap> swaps) {
        AuditIssueDefinition definition = issue.definition();
        return AuditIssue.auditIssue(issue.name(), issue.detail(), issue.remediation(),
                url, issue.severity(), issue.confidence(),
                definition.background(), definition.remediation(), definition.typicalSeverity(),
                swaps.stream().map(EvidenceSwap::evidence).toList());
    }

    private record EvidenceSwap(HttpRequestResponse proxied, Optional<HttpRequestResponse> upstream) {

        boolean swapped() {
            return upstream.isPresent();
        }

        HttpRequestResponse evidence() {
            return upstream.orElse(proxied);
        }

        String rebasedUrl(String baseUrl) {
            return Origin.of(baseUrl).filter(Origin.of(proxied.httpService())::equals)
                    .map(ignored -> upstream.orElseThrow().request().url())
                    .orElse(baseUrl);
        }
    }
}
