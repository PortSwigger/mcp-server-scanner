package com.mcpscanner.checks.shared.probe;

import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.responses.HttpResponse;
import com.mcpscanner.testutil.MontoyaTestFactory;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

class ServerErrorAnswerTest {

    private static final String CRASH = "{\"jsonrpc\":\"2.0\",\"id\":3,\"error\":{\"code\":-32603,\"message\":\"boom\"}}";

    @BeforeEach
    void installMontoya() {
        MontoyaTestFactory.install();
    }

    @Test
    void theSameServerErrorTwiceReproduces() {
        assertThat(ServerErrorAnswer.reproduces(answered("application/json", "", CRASH),
                answered("application/json", "", CRASH))).isTrue();
    }

    @Test
    void aDifferentServerErrorDoesNotReproduce() {
        assertThat(ServerErrorAnswer.reproduces(answered("application/json", "", CRASH),
                answered("application/json", "", CRASH.replace("boom", "other")))).isFalse();
    }

    @Test
    void streamedServerErrorsThatDifferOnlyInTheirEventIdsReproduce() {
        assertThat(ServerErrorAnswer.reproduces(answered("text/event-stream", "", event("a1")),
                answered("text/event-stream", "", event("b2")))).isTrue();
    }

    @Test
    void chunkedServerErrorsFramedDifferentlyReproduce() {
        String oneChunk = Integer.toHexString(CRASH.length()) + "\r\n" + CRASH + "\r\n0\r\n\r\n";
        String twoChunks = "4\r\n" + CRASH.substring(0, 4) + "\r\n" + Integer.toHexString(CRASH.length() - 4)
                + "\r\n" + CRASH.substring(4) + "\r\n0\r\n\r\n";

        assertThat(ServerErrorAnswer.reproduces(answered("application/json", "Transfer-Encoding: chunked\r\n", oneChunk),
                answered("application/json", "Transfer-Encoding: chunked\r\n", twoChunks))).isTrue();
    }

    private static String event(String eventId) {
        return "id: " + eventId + "\nevent: message\ndata: " + CRASH + "\n\n";
    }

    private static HttpRequestResponse answered(String contentType, String extraHeaders, String body) {
        return HttpRequestResponse.httpRequestResponse(
                SimulatedMcpServer.request(SimulatedMcpServer.toolCall(), Map.of()),
                HttpResponse.httpResponse("HTTP/1.1 500 X\r\nContent-Type: " + contentType + "\r\n" + extraHeaders
                        + "\r\n" + body));
    }
}
