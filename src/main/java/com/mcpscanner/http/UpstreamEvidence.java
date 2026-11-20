package com.mcpscanner.http;

import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.scanner.audit.issues.AuditIssue;
import burp.api.montoya.scanner.audit.issues.AuditIssueDefinition;

import java.util.ArrayList;
import java.util.Collections;
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
        String url = exchanges.issueUrl(first.map(swap -> swap.rebasedUrl(issue.baseUrl()))
                .orElseGet(() -> rebasedOffTheProxy(issue)));
        return first.isEmpty() && Objects.equals(url, issue.baseUrl()) ? issue : rebuilt(issue, url, swaps);
    }

    private String rebasedOffTheProxy(AuditIssue issue) {
        if (!exchanges.onProxy(issue.baseUrl())) {
            return issue.baseUrl();
        }
        return issue.requestResponses().stream().map(evidence -> evidence.request().url())
                .filter(url -> !exchanges.onProxy(url))
                .findFirst()
                .orElse(issue.baseUrl());
    }

    public List<HttpRequestResponse> resolved(HttpRequestResponse proxied) {
        return swap(proxied).evidence();
    }

    private EvidenceSwap swap(HttpRequestResponse proxied) {
        return new EvidenceSwap(proxied, exchanges.upstreamOf(proxied));
    }

    private static AuditIssue rebuilt(AuditIssue issue, String url, List<EvidenceSwap> swaps) {
        AuditIssueDefinition definition = issue.definition();
        return AuditIssue.auditIssue(issue.name(), detailOf(issue, swaps), issue.remediation(),
                url, issue.severity(), issue.confidence(),
                definition.background(), definition.remediation(), definition.typicalSeverity(),
                swaps.stream().flatMap(swap -> swap.evidence().stream()).toList());
    }

    private static String detailOf(AuditIssue issue, List<EvidenceSwap> swaps) {
        return swaps.stream().anyMatch(EvidenceSwap::split) ? SplitExchangeNote.addedTo(issue.detail())
                : issue.detail();
    }

    private record EvidenceSwap(HttpRequestResponse proxied, List<HttpRequestResponse> upstream) {

        boolean swapped() {
            return !upstream.isEmpty();
        }

        boolean split() {
            return upstream.size() > 1;
        }

        List<HttpRequestResponse> evidence() {
            return swapped() ? markedUpstream() : Collections.singletonList(proxied);
        }

        private List<HttpRequestResponse> markedUpstream() {
            List<HttpRequestResponse> items = new ArrayList<>(upstream.stream().map(EvidenceSwap::unmarked).toList());
            int last = items.size() - 1;
            items.set(0, TextMarkers.requestCarriedOver(proxied, items.get(0)));
            items.set(last, TextMarkers.responseCarriedOver(proxied, items.get(last)));
            return List.copyOf(items);
        }

        String rebasedUrl(String baseUrl) {
            return Origin.of(baseUrl).filter(Origin.of(proxied.httpService())::equals)
                    .map(ignored -> upstream.get(0).request().url())
                    .orElse(baseUrl);
        }

        private static HttpRequestResponse unmarked(HttpRequestResponse upstream) {
            return HttpRequestResponse.httpRequestResponse(upstream.request(), upstream.response(),
                    upstream.annotations());
        }
    }
}
