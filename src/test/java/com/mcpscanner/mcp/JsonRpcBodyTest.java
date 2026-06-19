package com.mcpscanner.mcp;

import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

class JsonRpcBodyTest {

    @Test
    void emptyParamsEmitsJsonRpc2EnvelopeWithEmptyParamsObject() {
        String body = JsonRpcBody.emptyParams("ping");

        assertThat(body).startsWith("{\"jsonrpc\":\"2.0\",\"id\":")
                .contains("\"method\":\"ping\"")
                .endsWith("\"params\":{}}");
    }

    @Test
    void singleStringParamEmitsEscapedKeyValueParams() {
        String body = JsonRpcBody.singleStringParam("resources/read", "uri", "file:///etc/passwd");

        assertThat(body).startsWith("{\"jsonrpc\":\"2.0\",\"id\":")
                .contains("\"method\":\"resources/read\"")
                .contains("\"uri\":\"file:///etc/passwd\"");
    }

    @Test
    void singleStringParamEscapesQuotesAndBackslashes() {
        String body = JsonRpcBody.singleStringParam("custom", "needle", "a\"b\\c");

        assertThat(body).contains("\"needle\":\"a\\\"b\\\\c\"");
    }

    @Test
    void emptyParamsIncrementsRequestIdAcrossCalls() {
        long first = idOf(JsonRpcBody.emptyParams("ping"));
        long second = idOf(JsonRpcBody.emptyParams("ping"));

        assertThat(second).isGreaterThan(first);
    }

    private static long idOf(String body) {
        // The id is the first number following ",\"id\":".
        int start = body.indexOf("\"id\":") + 5;
        int end = body.indexOf(',', start);
        return Long.parseLong(body.substring(start, end));
    }
}
