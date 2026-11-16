package com.mcpscanner.checks.catalog.sqlinjection;

import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import com.mcpscanner.testutil.MontoyaTestFactory;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

class ReplyShapeTest {

    @BeforeEach
    void installMontoya() {
        MontoyaTestFactory.install();
    }

    @Test
    void matchesTheSameReplyWhateverItsId() {
        assertThat(shape(1, 200, "rows", List.of()).matches(shape(9, 200, "rows", List.of()))).isTrue();
    }

    @Test
    void undoesTheReflectedValueBeforeComparing() {
        ReplyShape reflected = shape(1, 200, "Echo: notes/*q1*/", List.of(new Reflection("notes/*q1*/", "notes")));

        assertThat(reflected.matches(shape(1, 200, "Echo: notes", List.of()))).isTrue();
    }

    @Test
    void differsOnAnotherStatus() {
        assertThat(shape(1, 500, "rows", List.of()).differsFrom(shape(1, 200, "rows", List.of()))).isTrue();
    }

    @Test
    void anUnansweredOrRateLimitedReplyNeitherMatchesNorDiffers() {
        ReplyShape limited = shape(1, 429, "rows", List.of());
        ReplyShape answered = shape(1, 200, "rows", List.of());

        assertThat(limited.answered()).isFalse();
        assertThat(limited.matches(answered)).isFalse();
        assertThat(limited.differsFrom(answered)).isFalse();
        assertThat(answered.differsFrom(limited)).isFalse();
        assertThat(ReplyShape.of(null, List.of()).answered()).isFalse();
    }

    private static ReplyShape shape(int id, int status, String text, List<Reflection> reflections) {
        HttpRequest request = HttpRequest.httpRequestFromUrl("http://mcp.example/mcp").withMethod("POST")
                .withBody("{\"jsonrpc\":\"2.0\",\"id\":" + id + ",\"method\":\"tools/call\",\"params\":{}}");
        String body = "{\"jsonrpc\":\"2.0\",\"id\":" + id + ",\"result\":{\"content\":[{\"type\":\"text\",\"text\":\""
                + text + "\"}]}}";
        HttpResponse response = HttpResponse.httpResponse("HTTP/1.1 " + status + " X\r\nContent-Type: "
                + "application/json\r\n\r\n" + body);
        return ReplyShape.of(HttpRequestResponse.httpRequestResponse(request, response), reflections);
    }
}
