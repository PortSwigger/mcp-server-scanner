package com.mcpscanner.mcp;

import burp.api.montoya.http.HttpService;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class McpRequestDetectorTest {

    @Mock
    private HttpRequestResponse requestResponse;

    @Mock
    private HttpRequest request;

    @Mock
    private HttpService httpService;

    @Test
    void classifyReturnsToolsCallForToolsCallBody() {
        stubRequest("POST", "{\"jsonrpc\":\"2.0\",\"method\":\"tools/call\"}");

        assertThat(McpRequestDetector.classify(requestResponse)).isEqualTo(McpRequestKind.TOOLS_CALL);
    }

    @Test
    void classifyReturnsToolsListForToolsListBody() {
        stubRequest("POST", "{\"jsonrpc\":\"2.0\",\"method\":\"tools/list\"}");

        assertThat(McpRequestDetector.classify(requestResponse)).isEqualTo(McpRequestKind.TOOLS_LIST);
    }

    @Test
    void classifyReturnsResourcesReadForResourcesReadBody() {
        stubRequest("POST", "{\"jsonrpc\":\"2.0\",\"method\":\"resources/read\"}");

        assertThat(McpRequestDetector.classify(requestResponse)).isEqualTo(McpRequestKind.RESOURCES_READ);
    }

    @Test
    void classifyReturnsPromptsGetForPromptsGetBody() {
        stubRequest("POST", "{\"jsonrpc\":\"2.0\",\"method\":\"prompts/get\"}");

        assertThat(McpRequestDetector.classify(requestResponse)).isEqualTo(McpRequestKind.PROMPTS_GET);
    }

    @Test
    void classifyReturnsOtherMcpForResourcesList() {
        stubRequest("POST", "{\"jsonrpc\":\"2.0\",\"method\":\"resources/list\"}");

        assertThat(McpRequestDetector.classify(requestResponse)).isEqualTo(McpRequestKind.OTHER_MCP);
    }

    @Test
    void classifyReturnsOtherMcpForPromptsList() {
        stubRequest("POST", "{\"jsonrpc\":\"2.0\",\"method\":\"prompts/list\"}");

        assertThat(McpRequestDetector.classify(requestResponse)).isEqualTo(McpRequestKind.OTHER_MCP);
    }

    @Test
    void classifyReturnsOtherMcpForInitialize() {
        stubRequest("POST", "{\"jsonrpc\":\"2.0\",\"method\":\"initialize\"}");

        assertThat(McpRequestDetector.classify(requestResponse)).isEqualTo(McpRequestKind.OTHER_MCP);
    }

    @Test
    void classifyReturnsNotMcpForPlainText() {
        stubRequest("POST", "plain text without json rpc markers");

        assertThat(McpRequestDetector.classify(requestResponse)).isEqualTo(McpRequestKind.NOT_MCP);
    }

    @Test
    void classifyReturnsNotMcpForEmptyBody() {
        stubRequest("POST", "");

        assertThat(McpRequestDetector.classify(requestResponse)).isEqualTo(McpRequestKind.NOT_MCP);
    }

    @Test
    void classifyReturnsNotMcpForNonPost() {
        stubRequest("GET", "{\"jsonrpc\":\"2.0\",\"method\":\"tools/call\"}");

        assertThat(McpRequestDetector.classify(requestResponse)).isEqualTo(McpRequestKind.NOT_MCP);
    }

    @Test
    void classifyReturnsNotMcpForJsonRpcWithoutRecognisedMethod() {
        stubRequest("POST", "{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{}}");

        assertThat(McpRequestDetector.classify(requestResponse)).isEqualTo(McpRequestKind.NOT_MCP);
    }

    @Test
    void extractBaseUrlReturnsHttpsForSecureService() {
        when(requestResponse.request()).thenReturn(request);
        when(request.httpService()).thenReturn(httpService);
        when(httpService.secure()).thenReturn(true);
        when(httpService.host()).thenReturn("example.com");
        when(httpService.port()).thenReturn(443);

        assertThat(McpRequestDetector.extractBaseUrl(requestResponse)).isEqualTo("https://example.com");
    }

    @Test
    void extractBaseUrlIncludesNonDefaultPort() {
        when(requestResponse.request()).thenReturn(request);
        when(request.httpService()).thenReturn(httpService);
        when(httpService.secure()).thenReturn(false);
        when(httpService.host()).thenReturn("localhost");
        when(httpService.port()).thenReturn(8080);

        assertThat(McpRequestDetector.extractBaseUrl(requestResponse)).isEqualTo("http://localhost:8080");
    }

    @Test
    void isNotificationBodyIsTrueOnlyForMethodWithoutIdKey() {
        assertThat(McpRequestDetector.isNotificationBody("{\"jsonrpc\":\"2.0\",\"method\":\"notifications/initialized\"}")).isTrue();
        assertThat(McpRequestDetector.isNotificationBody("{\"jsonrpc\":\"2.0\",\"id\":null,\"method\":\"x\"}")).isFalse();
        assertThat(McpRequestDetector.isNotificationBody("not json")).isFalse();
    }

    @Test
    void isInitializeBodyIsTrueOnlyForASingleInitializeMessage() {
        assertThat(McpRequestDetector.isInitializeBody("{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"initialize\"}")).isTrue();
        assertThat(McpRequestDetector.isInitializeBody("{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/list\"}")).isFalse();
        assertThat(McpRequestDetector.isInitializeBody("not json")).isFalse();
    }

    @Test
    void isToolCallBodyIsTrueOnlyForASingleToolCallRequest() {
        assertThat(McpRequestDetector.isToolCallBody("{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/call\"}")).isTrue();
        assertThat(McpRequestDetector.isToolCallBody("{\"jsonrpc\":\"2.0\",\"method\":\"tools/call\"}")).isFalse();
        assertThat(McpRequestDetector.isToolCallBody("{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/list\"}")).isFalse();
        assertThat(McpRequestDetector.isToolCallBody("[{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/call\"}]")).isFalse();
        assertThat(McpRequestDetector.isToolCallBody("not json")).isFalse();
    }

    @Test
    void isInitializeBodyIsFalseForABatchBecauseInitializeMustNotBeBatched() {
        assertThat(McpRequestDetector.isInitializeBody(
                "[{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"initialize\",\"params\":{}}]")).isFalse();
    }

    private void stubRequest(String method, String body) {
        when(requestResponse.request()).thenReturn(request);
        when(request.method()).thenReturn(method);
        if ("POST".equalsIgnoreCase(method)) {
            when(request.bodyToString()).thenReturn(body);
        }
    }
}
