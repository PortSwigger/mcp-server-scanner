package com.mcpscanner;

import burp.api.montoya.http.message.requests.HttpRequest;
import com.mcpscanner.mcp.McpToolDefinition;
import com.mcpscanner.mcp.ResendableRequests;
import com.mcpscanner.mcp.ToolAnnotations;
import com.mcpscanner.testutil.MontoyaTestFactory;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

class ResendableBurpRequestsTest {

    private static final String MCP_URL = "https://mcp.example.com/mcp";
    private static final String TOOLS_LIST = "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/list\"}";

    private final ResendableRequests reads = new ResendableRequests();
    private final ResendableBurpRequests resendable = new ResendableBurpRequests();

    @BeforeEach
    void setUp() {
        MontoyaTestFactory.install();
        reads.learn(List.of(tool("get_weather", true), tool("delete_user", false)));
        resendable.bindTo(reads);
    }

    @ParameterizedTest
    @ValueSource(strings = {"GET", "HEAD", "OPTIONS", "get"})
    void aBodylessSafeMethodIsResendable(String method) {
        assertThat(resendable.test(bodyless(method))).isTrue();
    }

    @ParameterizedTest
    @ValueSource(strings = {"DELETE", "POST", "PUT", "PATCH"})
    void aBodylessUnsafeMethodIsNeverResendable(String method) {
        assertThat(resendable.test(bodyless(method))).isFalse();
    }

    @Test
    void aReadOrHandshakeIsResendable() {
        assertThat(resendable.test(posted(TOOLS_LIST))).isTrue();
    }

    @Test
    void aCallToAReadOnlyToolIsResendable() {
        assertThat(resendable.test(posted(toolCall("get_weather")))).isTrue();
    }

    @Test
    void aCallToAToolThatMayWriteIsNeverResendable() {
        assertThat(resendable.test(posted(toolCall("delete_user")))).isFalse();
    }

    @Test
    void nothingIsResendableBeforeTheScannerSessionIsBound() {
        assertThat(new ResendableBurpRequests().test(posted(TOOLS_LIST))).isFalse();
        assertThat(new ResendableBurpRequests().test(bodyless("GET"))).isFalse();
    }

    private static HttpRequest bodyless(String method) {
        return HttpRequest.httpRequestFromUrl(MCP_URL).withMethod(method);
    }

    private static HttpRequest posted(String body) {
        return HttpRequest.httpRequestFromUrl(MCP_URL).withMethod("POST").withBody(body);
    }

    private static String toolCall(String name) {
        return "{\"jsonrpc\":\"2.0\",\"id\":7,\"method\":\"tools/call\",\"params\":{\"name\":\"" + name + "\"}}";
    }

    private static McpToolDefinition tool(String name, boolean readOnly) {
        return new McpToolDefinition(name, "", "{}", List.of(), new ToolAnnotations(null, readOnly, null, null, null));
    }
}
