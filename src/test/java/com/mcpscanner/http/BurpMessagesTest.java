package com.mcpscanner.http;

import burp.api.montoya.core.ByteArray;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import com.mcpscanner.testutil.MontoyaTestFactory;
import com.mcpscanner.testutil.RecordingBurpRequest;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;

class BurpMessagesTest {

    private RecordingBurpRequest recorder;

    @BeforeEach
    void setUp() {
        MontoyaTestFactory.install();
        recorder = new RecordingBurpRequest();
    }

    @Test
    void bodyWithinLimitComparesTheFramedBodyLength() {
        ByteArray body = ByteArray.byteArray("12345");
        HttpResponse response = org.mockito.Mockito.mock(HttpResponse.class);
        org.mockito.Mockito.when(response.body()).thenReturn(body);

        assertThat(BurpMessages.bodyWithin(response, 5)).isTrue();
        assertThat(BurpMessages.bodyWithin(response, 4)).isFalse();
    }

    @Test
    void bodilessResponseIsWithinAnyLimit() {
        HttpResponse response = org.mockito.Mockito.mock(HttpResponse.class);
        org.mockito.Mockito.when(response.body()).thenReturn(null);

        assertThat(BurpMessages.bodyWithin(response, 0)).isTrue();
    }

    @Test
    void unframedBodyOfABodilessResponseIsEmpty() {
        HttpResponse response = org.mockito.Mockito.mock(HttpResponse.class);
        org.mockito.Mockito.when(response.body()).thenReturn(null);

        assertThat(BurpMessages.unframedBody(response)).isEmpty();
    }

    @Test
    void startsRequestFromUrlAndAppliesMethod() {
        HttpRequest request = recordingMessages().toRequest("https://mcp.example.com/mcp", "POST", Map.of(), null);

        assertThat(request).isSameAs(recorder.request());
        assertThat(recorder.startedUrl()).isEqualTo("https://mcp.example.com/mcp");
        assertThat(recorder.method()).isEqualTo("POST");
    }

    @Test
    void addsEveryHeaderValueInOrder() {
        Map<String, List<String>> headers = new LinkedHashMap<>();
        headers.put("Accept", List.of("application/json", "text/event-stream"));
        headers.put("Mcp-Session-Id", List.of("abc"));
        headers.put("X-Multi", List.of("one", "two"));

        recordingMessages().toRequest("https://mcp.example.com/mcp", "POST", headers, null);

        assertThat(recorder.addedHeaders()).containsExactly(
                "Accept: application/json",
                "Accept: text/event-stream",
                "Mcp-Session-Id: abc",
                "X-Multi: one",
                "X-Multi: two");
    }

    @Test
    void leavesTheConnectionHeaderToTheConnectionReusePolicy() {
        recordingMessages().toRequest("https://mcp.example.com/mcp", "POST", Map.of("CONNECTION", List.of("keep-alive")),
                null);

        assertThat(recorder.addedHeaders()).isEmpty();
    }

    @Test
    void setsNonAsciiBodyAsUtf8Bytes() {
        String json = "{\"name\":\"caf\u00e9 \u2603 \ud83d\ude80\"}";

        recordingMessages().toRequest("https://mcp.example.com/mcp", "POST", Map.of(), json);

        assertThat(recorder.bodyBytes()).isEqualTo(json.getBytes(StandardCharsets.UTF_8));
    }

    @Test
    void setsEmptyBodyWhenEmpty() {
        recordingMessages().toRequest("https://mcp.example.com/mcp", "POST", Map.of(), "");

        assertThat(recorder.bodyBytes()).isEmpty();
    }

    @Test
    void leavesBodyUnsetWhenNull() {
        recordingMessages().toRequest("https://mcp.example.com/mcp", "GET", Map.of(), null);

        verify(recorder.request(), never()).withBody(any(ByteArray.class));
        assertThat(recorder.bodyBytes()).isNull();
    }

    @Test
    void defaultStarterBuildsRequestFromUrl() {
        HttpRequest request = new BurpMessages().toRequest(
                "https://mcp.example.com/mcp", "GET", Map.of("Accept", List.of("application/json")), null);

        assertThat(request.method()).isEqualTo("GET");
        assertThat(request.url()).isEqualTo("https://mcp.example.com/mcp");
        assertThat(request.headerValue("Accept")).isEqualTo("application/json");
    }

    @Test
    void defaultStarterSendsOnlyHostAndTheGivenHeaders() {
        com.mcpscanner.testutil.BurpBrowserTemplate.installFor("http://127.0.0.1:18800/mcp");

        HttpRequest request = new BurpMessages().toRequest("http://127.0.0.1:18800/mcp", "POST",
                Map.of("Accept", List.of("application/json, text/event-stream")), "{}");

        assertThat(request.headers()).extracting(header -> header.name() + ": " + header.value())
                .containsExactly("Host: 127.0.0.1:18800", "Accept: application/json, text/event-stream");
    }

    @Test
    void groupsRepeatedResponseHeadersPreservingCasingAndOrder() {
        HttpResponse response = HttpResponse.httpResponse("HTTP/1.1 200 OK\r\n"
                + "Content-Type: application/json\r\n"
                + "Set-Cookie: a=1\r\n"
                + "mcp-session-id: xyz\r\n"
                + "Set-Cookie: b=2\r\n"
                + "\r\n"
                + "{}");

        Map<String, List<String>> grouped = BurpMessages.groupedHeaders(response);

        assertThat(grouped).containsOnlyKeys("Content-Type", "Set-Cookie", "mcp-session-id");
        assertThat(grouped.keySet()).containsExactly("Content-Type", "Set-Cookie", "mcp-session-id");
        assertThat(grouped.get("Set-Cookie")).containsExactly("a=1", "b=2");
        assertThat(grouped.get("mcp-session-id")).containsExactly("xyz");
    }

    @Test
    void groupsNoHeadersIntoEmptyMap() {
        HttpResponse response = HttpResponse.httpResponse("HTTP/1.1 204 No Content\r\n\r\n");

        assertThat(BurpMessages.groupedHeaders(response)).isEmpty();
    }

    private BurpMessages recordingMessages() {
        return new BurpMessages(recorder::startFrom);
    }
}
