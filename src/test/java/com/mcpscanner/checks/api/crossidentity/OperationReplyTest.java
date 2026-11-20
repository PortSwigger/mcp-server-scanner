package com.mcpscanner.checks.api.crossidentity;

import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.responses.HttpResponse;
import com.mcpscanner.testutil.ImmutableHttpRequest;
import com.mcpscanner.testutil.MontoyaTestFactory;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

class OperationReplyTest {

    private static final String CALL = "{\"jsonrpc\":\"2.0\",\"id\":4,\"method\":\"tools/call\",\"params\":{}}";
    private static final String RESULT =
            "{\"jsonrpc\":\"2.0\",\"id\":4,\"result\":{\"content\":[{\"type\":\"text\",\"text\":\"MARKER-42\"}]}}";

    @BeforeEach
    void installMontoya() {
        MontoyaTestFactory.install();
    }

    @Test
    void findsAMarkerSplitAcrossChunks() {
        int split = RESULT.indexOf("MARKER-42") + 3;
        String body = Integer.toHexString(split) + "\r\n" + RESULT.substring(0, split) + "\r\n"
                + Integer.toHexString(RESULT.length() - split) + "\r\n" + RESULT.substring(split) + "\r\n0\r\n\r\n";

        assertThat(OperationReply.of(exchange("application/json\r\nTransfer-Encoding: chunked", body))
                .contains("MARKER-42")).isTrue();
    }

    @Test
    void nonJsonRepliesThatDifferOnlyInTheirChunkFramingHaveTheSameSignature() {
        String oneChunk = "4\r\nnope\r\n0\r\n\r\n";
        String twoChunks = "2\r\nno\r\n2\r\npe\r\n0\r\n\r\n";

        assertThat(OperationReply.of(exchange("text/plain\r\nTransfer-Encoding: chunked", oneChunk)).signature())
                .isEqualTo(OperationReply.of(exchange("text/plain\r\nTransfer-Encoding: chunked", twoChunks))
                        .signature());
    }

    private static HttpRequestResponse exchange(String contentType, String body) {
        return HttpRequestResponse.httpRequestResponse(
                ImmutableHttpRequest.post("https://api.example.com/mcp", Map.of("Content-Type", "application/json"),
                        CALL),
                HttpResponse.httpResponse("HTTP/1.1 200 OK\r\nContent-Type: " + contentType + "\r\n\r\n" + body));
    }
}
