package com.mcpscanner.checks.shared.evidence;

import burp.api.montoya.core.ByteArray;
import burp.api.montoya.core.Marker;
import burp.api.montoya.core.Range;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.api.montoya.scanner.audit.insertionpoint.AuditInsertionPoint;
import com.mcpscanner.scan.McpInsertionPointProvider;
import com.mcpscanner.testutil.MontoyaTestFactory;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class PayloadHighlightsTest {

    private static final String PAYLOAD = "http://abc\"123.oastify.com/";

    @BeforeEach
    void setUp() {
        MontoyaTestFactory.install();
    }

    @Test
    void marksTheInsertedPayloadAsItAppearsInTheSentRequest() {
        HttpRequestResponse base = HttpRequestResponse.httpRequestResponse(HttpRequest.httpRequestFromUrl(
                "https://mcp.example.test/mcp").withMethod("POST").withBody(
                "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/call\",\"params\":{\"name\":\"fetch\","
                        + "\"arguments\":{\"url\":\"https://example.com\"}}}"), null);
        AuditInsertionPoint url = new McpInsertionPointProvider().provideInsertionPoints(base).stream()
                .filter(point -> point.name().endsWith("params.arguments.url")).findFirst().orElseThrow();
        HttpRequestResponse sent = HttpRequestResponse.httpRequestResponse(
                url.buildHttpRequestWithPayload(ByteArray.byteArray(PAYLOAD)), null);

        HttpRequestResponse marked = PayloadHighlights.ofPayload(sent, url, PAYLOAD);

        assertThat(texts(marked.request().toByteArray(), marked.requestMarkers()))
                .containsExactly("\"http://abc\\\"123.oastify.com/\"");
    }

    @Test
    void marksAShortPayloadWhereItWasInsertedRatherThanItsFirstOccurrence() {
        String body = "{\"jsonrpc\":\"2.0\",\"params\":{\"arguments\":{\"path\":\"a/./b\"}}}";
        HttpRequest built = HttpRequest.httpRequestFromUrl("https://mcp.example.test/mcp").withMethod("POST")
                .withBody(body);
        int inserted = built.toByteArray().toString().indexOf("a/./b") + 2;
        List<Range> highlight = List.of(Range.range(inserted, inserted + 1));
        AuditInsertionPoint segment = mock(AuditInsertionPoint.class);
        when(segment.buildHttpRequestWithPayload(org.mockito.ArgumentMatchers.any())).thenReturn(built);
        when(segment.issueHighlights(org.mockito.ArgumentMatchers.any())).thenReturn(highlight);
        HttpRequestResponse sent = HttpRequestResponse.httpRequestResponse(built, null);

        HttpRequestResponse marked = PayloadHighlights.ofPayload(sent, segment, ".");

        assertThat(marked.requestMarkers()).singleElement()
                .satisfies(marker -> assertThat(marker.range().startIndexInclusive()).isEqualTo(inserted));
    }

    @Test
    void leavesTheExchangeUnmarkedWhenTheInsertionPointCannotHighlight() {
        AuditInsertionPoint point = mock(AuditInsertionPoint.class);
        when(point.buildHttpRequestWithPayload(org.mockito.ArgumentMatchers.any()))
                .thenThrow(new UnsupportedOperationException());
        HttpRequestResponse sent = HttpRequestResponse.httpRequestResponse(
                HttpRequest.httpRequestFromUrl("https://mcp.example.test/mcp"), null);

        assertThat(PayloadHighlights.ofPayload(sent, point, PAYLOAD).requestMarkers()).isEmpty();
        assertThat(PayloadHighlights.ofPayload(null, point, PAYLOAD)).isNull();
    }

    @Test
    void marksTheProofInTheResponse() {
        HttpRequestResponse sent = HttpRequestResponse.httpRequestResponse(
                HttpRequest.httpRequestFromUrl("https://mcp.example.test/mcp"),
                HttpResponse.httpResponse("HTTP/1.1 200 OK\r\n\r\n{\"text\":\"root:x:0:0:root:/root:/bin/sh\"}"));

        HttpRequestResponse marked = PayloadHighlights.ofProof(sent, List.of("root:x:0:0:root:/root:/bin/sh"));

        assertThat(texts(marked.response().toByteArray(), marked.responseMarkers()))
                .containsExactly("root:x:0:0:root:/root:/bin/sh");
    }

    private static List<String> texts(ByteArray message, List<Marker> markers) {
        String text = new String(message.getBytes(), StandardCharsets.UTF_8);
        return markers.stream().map(marker -> text.substring(marker.range().startIndexInclusive(),
                marker.range().endIndexExclusive())).toList();
    }
}
