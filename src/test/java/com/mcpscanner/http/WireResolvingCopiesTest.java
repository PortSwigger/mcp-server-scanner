package com.mcpscanner.http;

import burp.api.montoya.http.HttpService;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.api.montoya.scanner.audit.issues.AuditIssue;
import burp.api.montoya.scanner.audit.issues.AuditIssueConfidence;
import burp.api.montoya.scanner.audit.issues.AuditIssueSeverity;
import com.mcpscanner.testutil.MontoyaTestFactory;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.ArrayList;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

class WireResolvingCopiesTest {

    private static final String PROXIED_URL = "http://127.0.0.1:40123/mcp";
    private static final String TARGET_URL = "https://mcp.example.test/mcp";
    private static final String OTHER_URL = "https://other.example.test/mcp";
    private static final String LEGACY_POST_URL = "https://mcp.example.test/messages?session_id=41";
    private static final String LEGACY_STREAM_URL = "https://mcp.example.test/sse";

    private final List<HttpRequestResponse> copied = new ArrayList<>();
    private final TempFileCopies copying = exchange -> {
        copied.add(exchange);
        return exchange;
    };

    @BeforeEach
    void setUp() {
        MontoyaTestFactory.install();
    }

    @Test
    void keepsTheUpstreamWireExchangeWhileItIsStillStoredSoALateIssueNeverNeedsTheStore() {
        HttpRequestResponse proxied = exchange("HTTP/1.1 200 \r\nContent-Type: application/json\r\n\r\n{}");
        HttpRequestResponse wire = exchange("HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\n\r\n");
        UpstreamExchanges stored = candidate -> candidate == proxied ? List.of(wire) : List.of();

        HttpRequestResponse kept = new WireResolvingCopies(copying, stored).kept(proxied);

        assertThat(kept.response().toByteArray().toString()).startsWith("HTTP/1.1 200 OK\r\n");
        assertThat(copied).singleElement().isSameAs(kept);
    }

    @Test
    void keepsTheExchangeAsItIsWhenNoUpstreamExchangeIsStoredForIt() {
        HttpRequestResponse direct = exchange("HTTP/1.1 200 OK\r\n\r\n{}");

        HttpRequestResponse kept = new WireResolvingCopies(copying, UpstreamExchanges.NONE).kept(direct);

        assertThat(kept).isSameAs(direct);
        assertThat(copied).containsExactly(direct);
    }

    @Test
    void keepsTheProxiedExchangeAndHandsTheExchangesCopiesOfEveryItemItResolvesTo() {
        HttpRequestResponse proxied = exchange("HTTP/1.1 200 \r\nContent-Type: application/json\r\n\r\n{}");
        HttpRequestResponse post = exchange("HTTP/1.1 202 Accepted\r\n\r\n");
        HttpRequestResponse event = exchange("HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\n\r\n");
        List<List<HttpRequestResponse>> handedBack = new ArrayList<>();
        UpstreamExchanges stored = new UpstreamExchanges() {
            @Override
            public List<HttpRequestResponse> upstreamOf(HttpRequestResponse candidate) {
                return candidate == proxied ? List.of(post, event) : List.of();
            }

            @Override
            public void keepResolved(HttpRequestResponse candidate, List<HttpRequestResponse> items) {
                assertThat(candidate).isSameAs(proxied);
                handedBack.add(items);
            }
        };

        HttpRequestResponse kept = new WireResolvingCopies(copying, stored).kept(proxied);

        assertThat(kept).isSameAs(proxied);
        assertThat(handedBack).singleElement().satisfies(items -> {
            assertThat(items).extracting(item -> item.response().toByteArray().toString())
                    .containsExactly("HTTP/1.1 202 Accepted\r\n\r\n",
                            "HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\n\r\n");
            assertThat(copied).containsAll(items);
        });
        assertThat(copied).contains(proxied);
    }

    @Test
    void forwardsResolvedItemsThroughTheStableUrlWrapper() {
        List<HttpRequestResponse> handedBack = new ArrayList<>();
        UpstreamExchanges stored = new UpstreamExchanges() {
            @Override
            public List<HttpRequestResponse> upstreamOf(HttpRequestResponse candidate) {
                return List.of();
            }

            @Override
            public void keepResolved(HttpRequestResponse candidate, List<HttpRequestResponse> items) {
                handedBack.addAll(items);
            }
        };
        HttpRequestResponse item = exchange("HTTP/1.1 202 Accepted\r\n\r\n");

        stored.filingIssuesUnder(url -> url).keepResolved(item, List.of(item));

        assertThat(handedBack).containsExactly(item);
    }

    @Test
    void anIssueOnAProxiedBaseWhoseProbeResolvesToOneWireExchangeIsFiledUnderTheTargetUrl() {
        HttpRequestResponse proxied = exchangeAt(PROXIED_URL, "HTTP/1.1 200 \r\nContent-Type: application/json\r\n\r\n{}");
        HttpRequestResponse wire = exchangeAt(TARGET_URL, "HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\n\r\n");
        UpstreamExchanges stored = ((UpstreamExchanges) candidate -> candidate == proxied ? List.of(wire) : List.of())
                .proxiedThrough(WireResolvingCopiesTest::proxyService);

        HttpRequestResponse kept = new WireResolvingCopies(copying, stored).kept(proxied);
        AuditIssue filed = new UpstreamEvidence(stored).translate(issueFiledUnder(PROXIED_URL, kept));

        assertThat(filed.baseUrl()).isEqualTo(TARGET_URL);
        assertThat(filed.requestResponses()).singleElement().isSameAs(kept);
    }

    @Test
    void anIssueOnALegacySseBaseWhoseProbeResolvesToTwoWireItemsIsFiledUnderThePostUrl() {
        HttpRequestResponse proxied = exchangeAt(PROXIED_URL, "HTTP/1.1 200 \r\nContent-Type: application/json\r\n\r\n{}");
        HttpRequestResponse post = exchangeAt(LEGACY_POST_URL, "HTTP/1.1 202 Accepted\r\n\r\n");
        HttpRequestResponse event = exchangeAt(LEGACY_STREAM_URL, "HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\n\r\n");
        List<HttpRequestResponse> resolved = new ArrayList<>();
        UpstreamExchanges stored = new UpstreamExchanges() {
            @Override
            public List<HttpRequestResponse> upstreamOf(HttpRequestResponse candidate) {
                return candidate == proxied ? List.of(post, event) : List.of();
            }

            @Override
            public void keepResolved(HttpRequestResponse candidate, List<HttpRequestResponse> items) {
                resolved.addAll(items);
            }
        }.proxiedThrough(WireResolvingCopiesTest::proxyService);

        HttpRequestResponse kept = new WireResolvingCopies(copying, stored).kept(proxied);
        AuditIssue filed = new UpstreamEvidence(stored).translate(issueFiledUnder(PROXIED_URL, kept));

        assertThat(filed.baseUrl()).isEqualTo(LEGACY_POST_URL);
        assertThat(filed.requestResponses()).extracting(item -> item.request().url())
                .containsExactly(LEGACY_POST_URL, LEGACY_STREAM_URL);
        assertThat(resolved).hasSize(2);
    }

    @Test
    void anIssueWhoseBaseUrlIsNotOnTheProxyKeepsItsBaseUrl() {
        HttpRequestResponse direct = exchangeAt(TARGET_URL, "HTTP/1.1 200 OK\r\n\r\n{}");
        UpstreamExchanges stored = UpstreamExchanges.NONE.proxiedThrough(WireResolvingCopiesTest::proxyService);

        HttpRequestResponse kept = new WireResolvingCopies(copying, stored).kept(direct);
        AuditIssue filed = new UpstreamEvidence(stored).translate(issueFiledUnder(OTHER_URL, kept));

        assertThat(filed.baseUrl()).isEqualTo(OTHER_URL);
    }

    private static HttpService proxyService() {
        return HttpService.httpService("127.0.0.1", 40123, false);
    }

    private static AuditIssue issueFiledUnder(String baseUrl, HttpRequestResponse evidence) {
        return AuditIssue.auditIssue("Late interaction", "Detail", "Fix", baseUrl, AuditIssueSeverity.HIGH,
                AuditIssueConfidence.FIRM, "Background", "Fix background", AuditIssueSeverity.HIGH,
                List.of(evidence));
    }

    private static HttpRequestResponse exchangeAt(String url, String response) {
        return HttpRequestResponse.httpRequestResponse(HttpRequest.httpRequestFromUrl(url),
                HttpResponse.httpResponse(response));
    }

    private static HttpRequestResponse exchange(String response) {
        return HttpRequestResponse.httpRequestResponse(HttpRequest.httpRequestFromUrl("http://upstream/messages"),
                HttpResponse.httpResponse(response));
    }
}
