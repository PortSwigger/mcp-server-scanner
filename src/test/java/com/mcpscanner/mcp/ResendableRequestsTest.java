package com.mcpscanner.mcp;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

class ResendableRequestsTest {

    private final ResendableRequests requests = new ResendableRequests();

    @ParameterizedTest
    @ValueSource(strings = {"initialize", "notifications/initialized", "ping", "server/discover", "tools/list",
            "resources/list", "resources/templates/list", "prompts/list", "resources/read", "prompts/get",
            "completion/complete"})
    void aReadOrHandshakeRequestIsResendable(String method) {
        assertThat(requests.resendable(request(method, "{}"))).isTrue();
    }

    @ParameterizedTest
    @ValueSource(strings = {"sampling/createMessage", "notifications/cancelled", "unknown/method"})
    void anyOtherMethodIsNotResendable(String method) {
        assertThat(requests.resendable(request(method, "{}"))).isFalse();
    }

    @Test
    void aCallToAKnownReadOnlyToolIsResendable() {
        requests.learn(List.of(tool("read_note", new ToolAnnotations(null, true, null, null, null))));

        assertThat(requests.resendable(toolCall("read_note"))).isTrue();
    }

    @Test
    void aCallToAKnownWriteToolIsNotResendable() {
        requests.learn(List.of(tool("write_note", ToolAnnotations.EMPTY),
                tool("get_note", new ToolAnnotations(null, false, null, null, null))));

        assertThat(requests.resendable(toolCall("write_note"))).isFalse();
        assertThat(requests.resendable(toolCall("get_note"))).isFalse();
    }

    @Test
    void aCallToAToolThatWasNeverListedIsNotResendable() {
        assertThat(requests.resendable(toolCall("read_note"))).isFalse();
    }

    @Test
    void forgettingTheToolsStopsResendingTheirCalls() {
        requests.learn(List.of(tool("read_note", ToolAnnotations.EMPTY)));

        requests.forget();

        assertThat(requests.resendable(toolCall("read_note"))).isFalse();
    }

    @ParameterizedTest
    @ValueSource(strings = {"", "not json", "[{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"ping\"}]",
            "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":7}"})
    void aBodyThatIsNotOneJsonRpcRequestIsNotResendable(String body) {
        assertThat(requests.resendable(body)).isFalse();
    }

    @ParameterizedTest
    @ValueSource(strings = {"GET", "HEAD", "OPTIONS", "get"})
    void aBodylessSafeHttpMethodIsResendable(String httpMethod) {
        assertThat(requests.resendable(httpMethod, null)).isTrue();
        assertThat(requests.resendable(httpMethod, "")).isTrue();
    }

    @ParameterizedTest
    @ValueSource(strings = {"DELETE", "POST", "PUT", "PATCH"})
    void aBodylessUnsafeHttpMethodIsNeverResendable(String httpMethod) {
        assertThat(requests.resendable(httpMethod, null)).isFalse();
        assertThat(requests.resendable(httpMethod, "")).isFalse();
    }

    @Test
    void aRequestWithABodyIsDecidedByItsJsonRpcMethod() {
        assertThat(requests.resendable("POST", request("tools/list", "{}"))).isTrue();
        assertThat(requests.resendable("POST", toolCall("write_note"))).isFalse();
    }

    private static McpToolDefinition tool(String name, ToolAnnotations annotations) {
        return new McpToolDefinition(name, "", "{}", List.of(), annotations);
    }

    private static String toolCall(String name) {
        return request("tools/call", "{\"name\":\"" + name + "\",\"arguments\":{}}");
    }

    private static String request(String method, String params) {
        return "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"" + method + "\",\"params\":" + params + "}";
    }
}
