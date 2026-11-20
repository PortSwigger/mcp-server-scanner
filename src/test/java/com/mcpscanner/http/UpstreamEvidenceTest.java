package com.mcpscanner.http;

import burp.api.montoya.collaborator.Interaction;
import burp.api.montoya.core.Marker;
import burp.api.montoya.http.HttpService;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.api.montoya.scanner.audit.issues.AuditIssue;
import burp.api.montoya.scanner.audit.issues.AuditIssueConfidence;
import burp.api.montoya.scanner.audit.issues.AuditIssueDefinition;
import burp.api.montoya.scanner.audit.issues.AuditIssueSeverity;
import com.mcpscanner.testutil.ImmutableHttpRequest;
import com.mcpscanner.testutil.MontoyaTestFactory;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.util.IdentityHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.mock;

class UpstreamEvidenceTest {

    private static final String PROXY_URL = "http://127.0.0.1:40123/mcp";
    private static final String TARGET_URL = "https://mcp.example.test/mcp";

    private final Map<HttpRequestResponse, HttpRequestResponse> upstream = new IdentityHashMap<>();
    private final Map<HttpRequestResponse, List<HttpRequestResponse>> legacySse = new IdentityHashMap<>();
    private final UpstreamEvidence evidence = new UpstreamEvidence(this::lookup);

    @BeforeEach
    void setUp() {
        MontoyaTestFactory.install();
    }

    @Test
    void swapsTaggedEvidenceForTheUpstreamExchangeAndKeepsUntaggedEvidence() {
        HttpRequestResponse proxied = exchange(PROXY_URL, "proxied");
        HttpRequestResponse direct = exchange(TARGET_URL, "direct");
        HttpRequestResponse target = exchange(TARGET_URL, "target");
        upstream.put(proxied, target);

        AuditIssue translated = evidence.translate(issue(TARGET_URL, proxied, direct));

        assertThat(translated.requestResponses()).hasSize(2);
        assertThat(translated.requestResponses().get(0).request()).isSameAs(target.request());
        assertThat(translated.requestResponses().get(0).response()).isSameAs(target.response());
        assertThat(translated.requestResponses().get(1)).isSameAs(direct);
    }

    @Test
    void preservesTheIssueTextRatingsAndDefinition() {
        HttpRequestResponse proxied = exchange(PROXY_URL, "proxied");
        upstream.put(proxied, exchange(TARGET_URL, "target"));
        AuditIssue original = issue(TARGET_URL, proxied);

        AuditIssue translated = evidence.translate(original);

        assertThat(translated.name()).isEqualTo("Name");
        assertThat(translated.detail()).isEqualTo("Detail");
        assertThat(translated.remediation()).isEqualTo("Remediation");
        assertThat(translated.severity()).isEqualTo(AuditIssueSeverity.HIGH);
        assertThat(translated.confidence()).isEqualTo(AuditIssueConfidence.FIRM);
        assertThat(translated.definition().background()).isEqualTo("Background");
    }

    @Test
    void dropsTheUpstreamExchangesOwnMarkersWhenTheProxiedEvidenceHasNone() {
        HttpRequestResponse proxied = exchange(PROXY_URL, "proxied");
        upstream.put(proxied, marked(exchange(TARGET_URL, "target")));

        HttpRequestResponse swapped = evidence.translate(issue(TARGET_URL, proxied)).requestResponses().get(0);

        assertThat(swapped.requestMarkers()).isEmpty();
        assertThat(swapped.responseMarkers()).isEmpty();
    }

    @Test
    void carriesTheMarkedPayloadAndProofOverToTheUpstreamExchange() {
        HttpRequestResponse proxied = TextMarkers.inResponse(TextMarkers.inRequest(
                real(PROXY_URL, "{\"id\":1,\"q\":\"PAYLOAD\"}", "{\"r\":\"PROOF\"}"), List.of("PAYLOAD")),
                List.of("PROOF"));
        HttpRequestResponse target = real(TARGET_URL, "{\"id\":\"mcp-9\",\"q\":\"PAYLOAD\"}",
                "{\"jsonrpc\":\"2.0\",\"r\":\"PROOF\"}");
        upstream.put(proxied, target);

        HttpRequestResponse swapped = evidence.translate(issue(TARGET_URL, proxied)).requestResponses().get(0);

        assertThat(swapped.request()).isSameAs(target.request());
        assertThat(marked(swapped.request().toByteArray(), swapped.requestMarkers())).containsExactly("PAYLOAD");
        assertThat(marked(swapped.response().toByteArray(), swapped.responseMarkers())).containsExactly("PROOF");
    }

    @Test
    void keepsTheUpstreamExchangesTruncationNote() {
        HttpRequestResponse proxied = exchange(PROXY_URL, "proxied");
        HttpRequestResponse target = com.mcpscanner.http.evidence.WireRecord.ofSocket(
                HttpService.httpService(TARGET_URL),
                "POST /mcp HTTP/1.1\r\nHost: mcp.example.test\r\n\r\n{}".getBytes(StandardCharsets.ISO_8859_1),
                "HTTP/1.1 200 OK\r\n\r\nabc".getBytes(StandardCharsets.ISO_8859_1), true).evidence();
        upstream.put(proxied, target);

        HttpRequestResponse swapped = evidence.translate(issue(TARGET_URL, proxied)).requestResponses().get(0);

        assertThat(swapped.annotations().notes()).isEqualTo(target.annotations().notes()).isNotBlank();
    }

    private static List<String> marked(burp.api.montoya.core.ByteArray message, List<Marker> markers) {
        String text = new String(message.getBytes(), java.nio.charset.StandardCharsets.UTF_8);
        return markers.stream().map(marker -> text.substring(marker.range().startIndexInclusive(),
                marker.range().endIndexExclusive())).toList();
    }

    private static HttpRequestResponse real(String url, String requestBody, String responseBody) {
        return HttpRequestResponse.httpRequestResponse(
                HttpRequest.httpRequestFromUrl(url).withMethod("POST").withBody(requestBody),
                HttpResponse.httpResponse("HTTP/1.1 200 OK\r\n\r\n" + responseBody));
    }

    @Test
    void rewritesABaseUrlThatPointedAtTheProxyToTheFirstSwappedExchangesUrl() {
        HttpRequestResponse first = exchange(PROXY_URL, "first");
        HttpRequestResponse second = exchange(PROXY_URL, "second");
        upstream.put(first, exchange(TARGET_URL, "first-target"));
        upstream.put(second, exchange("https://other.example.test/mcp", "second-target"));

        AuditIssue translated = evidence.translate(issue(PROXY_URL, first, second));

        assertThat(translated.baseUrl()).isEqualTo("https://mcp.example.test:443/mcp");
    }

    @Test
    void keepsABaseUrlThatPointedElsewhere() {
        HttpRequestResponse proxied = exchange(PROXY_URL, "proxied");
        upstream.put(proxied, exchange("https://other.example.test/mcp", "target"));

        AuditIssue translated = evidence.translate(issue(TARGET_URL, proxied));

        assertThat(translated.baseUrl()).isEqualTo(TARGET_URL);
    }

    @Test
    void filesAnIssueUnderTheStableUrlKeepingTheEvidenceAsSent() {
        HttpRequestResponse direct = exchange("https://mcp.example.test/mcp/sessions/41", "direct");
        UpstreamExchanges stable = UpstreamExchanges.NONE
                .filingIssuesUnder(url -> url.replace("/sessions/41", "/sessions"));

        AuditIssue translated = new UpstreamEvidence(stable).translate(issue(direct.request().url(), direct));

        assertThat(translated.baseUrl()).endsWith("mcp.example.test:443/mcp/sessions");
        assertThat(translated.requestResponses()).containsExactly(direct);
    }

    @Test
    void filesASwappedIssueUnderTheStableFormOfTheUpstreamUrl() {
        HttpRequestResponse proxied = exchange(PROXY_URL, "proxied");
        upstream.put(proxied, exchange("https://mcp.example.test/mcp/sessions/77", "target"));
        UpstreamExchanges stable = ((UpstreamExchanges) this::lookup)
                .filingIssuesUnder(url -> url.replaceAll("/sessions/\\d+$", "/sessions"));

        AuditIssue translated = new UpstreamEvidence(stable).translate(issue(PROXY_URL, proxied));

        assertThat(translated.baseUrl()).isEqualTo("https://mcp.example.test:443/mcp/sessions");
    }

    @Test
    void returnsTheSameIssueWhenNothingIsTagged() {
        AuditIssue original = issue(TARGET_URL, exchange(TARGET_URL, "direct"));

        assertThat(evidence.translate(original)).isSameAs(original);
    }

    @Test
    void anEmptyLookupKeepsTheProxyView() {
        AuditIssue original = issue(PROXY_URL, exchange(PROXY_URL, "evicted"));

        AuditIssue translated = new UpstreamEvidence(UpstreamExchanges.NONE).translate(original);

        assertThat(translated).isSameAs(original);
        assertThat(translated.baseUrl()).isEqualTo(PROXY_URL);
    }

    @Test
    void translatesAnIssueCarryingCollaboratorInteractionsBecauseBurpDropsThemFromExtensionIssues() {
        HttpRequestResponse proxied = exchange(PROXY_URL, "proxied");
        HttpRequestResponse target = exchange(TARGET_URL, "target");
        upstream.put(proxied, target);
        AuditIssue original = issue(TARGET_URL, proxied);
        lenient().when(original.collaboratorInteractions()).thenReturn(List.of(mock(Interaction.class)));

        assertThat(evidence.translate(original).requestResponses().get(0).request()).isSameAs(target.request());
    }

    @Test
    void translatesEveryIssueInAList() {
        HttpRequestResponse proxied = exchange(PROXY_URL, "proxied");
        HttpRequestResponse target = exchange(TARGET_URL, "target");
        upstream.put(proxied, target);
        AuditIssue untouched = issue(TARGET_URL, exchange(TARGET_URL, "direct"));

        List<AuditIssue> translated = evidence.translate(List.of(issue(TARGET_URL, proxied), untouched));

        assertThat(translated.get(0).requestResponses().get(0).request()).isSameAs(target.request());
        assertThat(translated.get(1)).isSameAs(untouched);
    }

    @Test
    void aLegacySseExchangeBecomesThePostThenTheStreamEventWithThePayloadMarkedInTheFirstAndTheProofInTheLast() {
        HttpRequestResponse proxied = TextMarkers.inResponse(TextMarkers.inRequest(
                real(PROXY_URL, "{\"id\":1,\"q\":\"PAYLOAD\"}", "{\"r\":\"PROOF\"}"), List.of("PAYLOAD")),
                List.of("PROOF"));
        HttpRequestResponse post = real(TARGET_URL + "/messages", "{\"id\":\"mcp-9\",\"q\":\"PAYLOAD\"}", "");
        HttpRequestResponse event = HttpRequestResponse.httpRequestResponse(
                HttpRequest.httpRequestFromUrl(TARGET_URL + "/sse"),
                HttpResponse.httpResponse("HTTP/1.1 200 OK\r\n\r\nevent: message\r\ndata: {\"r\":\"PROOF\"}\r\n\r\n"));
        legacySse.put(proxied, List.of(post, event));

        AuditIssue translated = evidence.translate(issue(TARGET_URL, proxied));

        List<HttpRequestResponse> items = translated.requestResponses();
        assertThat(items).hasSize(2);
        assertThat(items.get(0).request()).isSameAs(post.request());
        assertThat(marked(items.get(0).request().toByteArray(), items.get(0).requestMarkers())).containsExactly("PAYLOAD");
        assertThat(items.get(0).responseMarkers()).isEmpty();
        assertThat(items.get(1).request()).isSameAs(event.request());
        assertThat(items.get(1).requestMarkers()).isEmpty();
        assertThat(marked(items.get(1).response().toByteArray(), items.get(1).responseMarkers())).containsExactly("PROOF");
    }

    @Test
    void anIssueWithASplitExchangeSaysOnceHowEachExchangeIsShown() {
        HttpRequestResponse base = exchange(PROXY_URL, "base");
        HttpRequestResponse probe = exchange(PROXY_URL, "probe");
        legacySse.put(base, List.of(exchange(TARGET_URL, "post"), exchange(TARGET_URL, "event")));
        legacySse.put(probe, List.of(exchange(TARGET_URL, "post"), exchange(TARGET_URL, "event")));

        AuditIssue translated = evidence.translate(issue(TARGET_URL, base, probe));

        assertThat(translated.requestResponses()).hasSize(4);
        assertThat(translated.detail()).isEqualTo("Detail" + SplitExchangeNote.DETAIL_SENTENCE);
    }

    @Test
    void anIssueWhoseDetailAlreadySaysHowExchangesAreSplitIsNotToldAgain() {
        HttpRequestResponse proxied = exchange(PROXY_URL, "proxied");
        legacySse.put(proxied, List.of(exchange(TARGET_URL, "post"), exchange(TARGET_URL, "event")));
        AuditIssue said = issue(TARGET_URL, proxied);
        lenient().when(said.detail()).thenReturn("Detail" + SplitExchangeNote.DETAIL_SENTENCE);

        assertThat(evidence.translate(said).detail()).isEqualTo("Detail" + SplitExchangeNote.DETAIL_SENTENCE);
    }

    @Test
    void aSingleItemSwapLeavesTheDetailAsWritten() {
        HttpRequestResponse proxied = exchange(PROXY_URL, "proxied");
        upstream.put(proxied, exchange(TARGET_URL, "target"));

        assertThat(evidence.translate(issue(TARGET_URL, proxied)).detail()).isEqualTo("Detail");
    }

    @Test
    void resolvesAProxiedExchangeToEveryUpstreamItemOrToItselfWhenNoneIsStored() {
        HttpRequestResponse proxied = exchange(PROXY_URL, "proxied");
        HttpRequestResponse unknown = exchange(PROXY_URL, "unknown");
        HttpRequestResponse post = exchange(TARGET_URL, "post");
        HttpRequestResponse event = exchange(TARGET_URL, "event");
        legacySse.put(proxied, List.of(post, event));

        assertThat(evidence.resolved(proxied)).extracting(HttpRequestResponse::request)
                .containsExactly(post.request(), event.request());
        assertThat(evidence.resolved(unknown)).containsExactly(unknown);
    }

    private List<HttpRequestResponse> lookup(HttpRequestResponse proxied) {
        return legacySse.containsKey(proxied) ? legacySse.get(proxied)
                : Optional.ofNullable(upstream.get(proxied)).map(List::of).orElse(List.of());
    }

    private static HttpRequestResponse exchange(String url, String body) {
        return HttpRequestResponse.httpRequestResponse(
                ImmutableHttpRequest.post(url, Map.of(), body), mock(HttpResponse.class));
    }

    private static HttpRequestResponse marked(HttpRequestResponse exchange) {
        HttpRequest request = exchange.request();
        HttpResponse response = exchange.response();
        HttpService service = request.httpService();
        HttpRequestResponse marked = mock(HttpRequestResponse.class);
        lenient().when(marked.request()).thenReturn(request);
        lenient().when(marked.response()).thenReturn(response);
        lenient().when(marked.httpService()).thenReturn(service);
        lenient().when(marked.requestMarkers()).thenReturn(List.of(mock(Marker.class)));
        lenient().when(marked.responseMarkers()).thenReturn(List.of(mock(Marker.class)));
        return marked;
    }

    private static AuditIssue issue(String baseUrl, HttpRequestResponse... evidence) {
        AuditIssue issue = mock(AuditIssue.class);
        lenient().when(issue.name()).thenReturn("Name");
        lenient().when(issue.detail()).thenReturn("Detail");
        lenient().when(issue.remediation()).thenReturn("Remediation");
        lenient().when(issue.baseUrl()).thenReturn(baseUrl);
        lenient().when(issue.severity()).thenReturn(AuditIssueSeverity.HIGH);
        lenient().when(issue.confidence()).thenReturn(AuditIssueConfidence.FIRM);
        lenient().when(issue.requestResponses()).thenReturn(List.of(evidence));
        AuditIssueDefinition definition = mock(AuditIssueDefinition.class);
        lenient().when(definition.background()).thenReturn("Background");
        lenient().when(definition.remediation()).thenReturn("Remediation background");
        lenient().when(definition.typicalSeverity()).thenReturn(AuditIssueSeverity.MEDIUM);
        lenient().when(issue.definition()).thenReturn(definition);
        return issue;
    }
}
