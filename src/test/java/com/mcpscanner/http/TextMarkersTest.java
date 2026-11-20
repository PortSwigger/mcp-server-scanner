package com.mcpscanner.http;

import burp.api.montoya.core.ByteArray;
import burp.api.montoya.core.Marker;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import com.mcpscanner.testutil.MontoyaTestFactory;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

class TextMarkersTest {

    @BeforeEach
    void setUp() {
        MontoyaTestFactory.install();
    }

    @Test
    void marksEveryOccurrenceOfATextInTheResponse() {
        HttpRequestResponse exchange = exchange("{\"q\":\"x\"}", "{\"out\":\"4242 and 4242\"}");

        HttpRequestResponse marked = TextMarkers.inResponse(exchange, List.of("4242"));

        assertThat(texts(marked.response().toByteArray(), marked.responseMarkers())).containsExactly("4242", "4242");
    }

    @Test
    void marksATextInTheRequest() {
        HttpRequestResponse exchange = exchange("{\"q\":\"$((6*7))\"}", "{}");

        HttpRequestResponse marked = TextMarkers.inRequest(exchange, List.of("\"$((6*7))\""));

        assertThat(texts(marked.request().toByteArray(), marked.requestMarkers())).containsExactly("\"$((6*7))\"");
    }

    @Test
    void leavesAnExchangeUnmarkedWhenTheTextIsAbsent() {
        HttpRequestResponse exchange = exchange("{}", "{}");

        assertThat(TextMarkers.inResponse(exchange, List.of("absent")).responseMarkers()).isEmpty();
    }

    @Test
    void toleratesAMissingExchangeOrResponse() {
        assertThat(TextMarkers.inResponse(null, List.of("x"))).isNull();
        HttpRequestResponse unanswered = HttpRequestResponse.httpRequestResponse(request("{}"), null);

        assertThat(TextMarkers.inResponse(unanswered, List.of("x"))).isSameAs(unanswered);
    }

    @Test
    void carriesMarkedTextOverToAnotherExchangeAtItsOwnOffsets() {
        HttpRequestResponse proxied = TextMarkers.inResponse(TextMarkers.inRequest(
                exchange("{\"id\":1,\"q\":\"PAYLOAD\"}", "{\"r\":\"PROOF\"}"), List.of("PAYLOAD")), List.of("PROOF"));
        HttpRequestResponse upstream = exchange("{\"id\":\"mcp-7\",\"_meta\":{},\"q\":\"PAYLOAD\"}",
                "{\"jsonrpc\":\"2.0\",\"r\":\"PROOF\"}");

        HttpRequestResponse carried = TextMarkers.carriedOver(proxied, upstream);

        assertThat(texts(carried.request().toByteArray(), carried.requestMarkers())).containsExactly("PAYLOAD");
        assertThat(texts(carried.response().toByteArray(), carried.responseMarkers())).containsExactly("PROOF");
    }

    @Test
    void carriesAnAnchoredMarkerOverAsTheSameSingleMarker() {
        String body = "{\"jsonrpc\":\"2.0\",\"id\":1,\"params\":{\"path\":\".\"}}";
        HttpRequest sent = request(body).withAddedHeader("X-Routing", "a.b.c");
        int payload = sent.toByteArray().toString().lastIndexOf("\".\"") + 1;
        HttpRequestResponse anchored = HttpRequestResponse.httpRequestResponse(sent, null)
                .withRequestMarkers(List.of(Marker.marker(payload, payload + 1)));
        HttpRequest cleaned = sent.withRemovedHeader("X-Routing");

        HttpRequestResponse carried = TextMarkers.carriedOver(anchored,
                HttpRequestResponse.httpRequestResponse(cleaned, null));

        int expected = cleaned.toByteArray().toString().lastIndexOf("\".\"") + 1;
        assertThat(carried.requestMarkers()).singleElement().satisfies(marker -> {
            assertThat(marker.range().startIndexInclusive()).isEqualTo(expected);
            assertThat(marker.range().endIndexExclusive()).isEqualTo(expected + 1);
        });
    }

    @Test
    void carriesTwoMarkersOfTheSameTextToTwoDistinctPlacesInOrder() {
        HttpRequestResponse proxied = TextMarkers.inResponse(exchange("{}", "{\"a\":\"PROOF\",\"b\":\"PROOF\"}"),
                List.of("PROOF"));
        HttpRequestResponse upstream = exchange("{}", "{\"jsonrpc\":\"2.0\",\"padding\":\"" + "x".repeat(80)
                + "\",\"z\":\"PROOF\",\"y\":\"PROOF\"}");

        HttpRequestResponse carried = TextMarkers.carriedOver(proxied, upstream);

        assertThat(carried.responseMarkers()).extracting(marker -> marker.range().startIndexInclusive())
                .doesNotHaveDuplicates().isSorted().hasSize(2);
    }

    @Test
    void carriesNothingFromAnUnmarkedExchange() {
        HttpRequestResponse upstream = exchange("{}", "{}");

        HttpRequestResponse carried = TextMarkers.carriedOver(exchange("{}", "{}"), upstream);

        assertThat(carried.requestMarkers()).isEmpty();
        assertThat(carried.responseMarkers()).isEmpty();
    }

    private static List<String> texts(ByteArray message, List<Marker> markers) {
        String text = new String(message.getBytes(), java.nio.charset.StandardCharsets.UTF_8);
        return markers.stream()
                .map(marker -> text.substring(marker.range().startIndexInclusive(), marker.range().endIndexExclusive()))
                .toList();
    }

    private static HttpRequestResponse exchange(String requestBody, String responseBody) {
        return HttpRequestResponse.httpRequestResponse(request(requestBody),
                HttpResponse.httpResponse("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n" + responseBody));
    }

    private static HttpRequest request(String body) {
        return HttpRequest.httpRequestFromUrl("https://mcp.example.test/mcp").withMethod("POST").withBody(body);
    }
}
