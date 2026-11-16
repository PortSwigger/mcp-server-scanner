package com.mcpscanner.access.comparison;

import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.responses.HttpResponse;
import com.mcpscanner.checks.api.crossidentity.OperationReply;
import com.mcpscanner.testutil.MontoyaTestFactory;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import static com.mcpscanner.checks.api.crossidentity.FakeMcpTarget.toolCall;
import static org.assertj.core.api.Assertions.assertThat;

class UnusableReplyTest {

    @BeforeEach
    void installMontoya() {
        MontoyaTestFactory.install();
    }

    @Test
    void noResponse() {
        assertThat(UnusableReply.describe(OperationReply.none())).isEqualTo("got no response");
    }

    @Test
    void httpFailureWithoutJsonRpc() {
        assertThat(UnusableReply.describe(reply(500, "oops"))).isEqualTo("returned HTTP 500");
    }

    @Test
    void emptyResult() {
        assertThat(UnusableReply.describe(reply(200,
                "{\"jsonrpc\":\"2.0\",\"id\":7,\"result\":{\"content\":[]}}"))).isEqualTo("returned an empty result");
    }

    @Test
    void longErrorTextIsCappedOnOneLine() {
        String message = "line one\n" + "x".repeat(300);
        String described = UnusableReply.describe(reply(200,
                "{\"jsonrpc\":\"2.0\",\"id\":7,\"error\":{\"code\":-32602,\"message\":\"" + message.replace("\n", "\\n")
                        + "\"}}"));

        assertThat(described).startsWith("returned a JSON-RPC error: line one xxx").endsWith("…")
                .hasSize("returned a JSON-RPC error: ".length() + UnusableReply.MAX_DETAIL + 1);
    }

    private static OperationReply reply(int status, String body) {
        HttpResponse response = HttpResponse.httpResponse("HTTP/1.1 " + status + " X\r\nContent-Type: "
                + "application/json\r\n\r\n" + body);
        return OperationReply.of(HttpRequestResponse.httpRequestResponse(toolCall("run_query", "{}", "A"),
                response));
    }
}
