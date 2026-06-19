package com.mcpscanner.mcp;

import burp.api.montoya.http.HttpService;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import com.mcpscanner.mcp.McpRequestDetector.DiscoveryResponseKind;
import com.mcpscanner.mcp.McpRequestDetector.ResponseContentKind;
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

    @Mock
    private HttpResponse response;

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
    void buildHostHeaderOmitsDefaultHttpPort() {
        when(httpService.secure()).thenReturn(false);
        when(httpService.host()).thenReturn("localhost");
        when(httpService.port()).thenReturn(80);

        assertThat(McpRequestDetector.buildHostHeader(httpService)).isEqualTo("localhost");
    }

    @Test
    void buildHostHeaderIncludesNonDefaultPort() {
        when(httpService.secure()).thenReturn(false);
        when(httpService.host()).thenReturn("localhost");
        when(httpService.port()).thenReturn(8080);

        assertThat(McpRequestDetector.buildHostHeader(httpService)).isEqualTo("localhost:8080");
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
    void isNonErrorMcpResponseReturnsFalseForNullResponse() {
        when(requestResponse.response()).thenReturn(null);

        assertThat(McpRequestDetector.isNonErrorMcpResponse(requestResponse)).isFalse();
    }

    @Test
    void isNonErrorMcpResponseReturnsFalseForNon200() {
        when(requestResponse.response()).thenReturn(response);
        when(response.statusCode()).thenReturn((short) 403);

        assertThat(McpRequestDetector.isNonErrorMcpResponse(requestResponse)).isFalse();
    }

    @Test
    void isNonErrorMcpResponseReturnsFalseForJsonRpcError() {
        when(requestResponse.response()).thenReturn(response);
        when(response.statusCode()).thenReturn((short) 200);
        when(response.bodyToString()).thenReturn("{\"jsonrpc\":\"2.0\",\"error\":{\"code\":-32602,\"message\":\"Invalid params\"}}");

        assertThat(McpRequestDetector.isNonErrorMcpResponse(requestResponse)).isFalse();
    }

    @Test
    void isNonErrorMcpResponseReturnsTrueFor200WithResult() {
        when(requestResponse.response()).thenReturn(response);
        when(response.statusCode()).thenReturn((short) 200);
        when(response.bodyToString()).thenReturn("{\"jsonrpc\":\"2.0\",\"result\":{\"tools\":[]}}");

        assertThat(McpRequestDetector.isNonErrorMcpResponse(requestResponse)).isTrue();
    }

    @Test
    void isNonErrorMcpResponseReturnsTrueWhenErrorWordInResultContent() {
        when(requestResponse.response()).thenReturn(response);
        when(response.statusCode()).thenReturn((short) 200);
        when(response.bodyToString()).thenReturn("{\"jsonrpc\":\"2.0\",\"result\":{\"content\":\"error handling tool\"}}");

        assertThat(McpRequestDetector.isNonErrorMcpResponse(requestResponse)).isTrue();
    }

    // ---------------------------------------------------------------------------------------
    // Strict isMcpResponseSuccess gate — requires 200 + jsonrpc:"2.0" + result + no error.
    // Distinct semantics from the looser isNonErrorMcpResponse above; both contracts locked
    // in by tests so callers can't drift between the two by accident.
    // ---------------------------------------------------------------------------------------

    @Test
    void isMcpResponseSuccess_returnsFalseForNullResponse() {
        when(requestResponse.response()).thenReturn(null);

        assertThat(McpRequestDetector.isMcpResponseSuccess(requestResponse)).isFalse();
    }

    @Test
    void isMcpResponseSuccess_returnsFalseForNon200() {
        when(requestResponse.response()).thenReturn(response);
        when(response.statusCode()).thenReturn((short) 500);

        assertThat(McpRequestDetector.isMcpResponseSuccess(requestResponse)).isFalse();
    }

    @Test
    void isMcpResponseSuccess_returnsFalseFor200WithoutJsonrpcField() {
        // Stricter than isNonErrorMcpResponse: missing "jsonrpc":"2.0" is rejected here.
        when(requestResponse.response()).thenReturn(response);
        when(response.statusCode()).thenReturn((short) 200);
        when(response.bodyToString()).thenReturn("{\"result\":{\"tools\":[]}}");

        assertThat(McpRequestDetector.isMcpResponseSuccess(requestResponse)).isFalse();
    }

    @Test
    void isMcpResponseSuccess_returnsFalseFor200WithoutResultField() {
        // Stricter than isNonErrorMcpResponse: no error AND no result is rejected here.
        when(requestResponse.response()).thenReturn(response);
        when(response.statusCode()).thenReturn((short) 200);
        when(response.bodyToString()).thenReturn("{\"jsonrpc\":\"2.0\",\"id\":1}");

        assertThat(McpRequestDetector.isMcpResponseSuccess(requestResponse)).isFalse();
    }

    @Test
    void isMcpResponseSuccess_returnsFalseFor200WithExplicitError() {
        when(requestResponse.response()).thenReturn(response);
        when(response.statusCode()).thenReturn((short) 200);
        when(response.bodyToString()).thenReturn(
                "{\"jsonrpc\":\"2.0\",\"id\":1,\"error\":{\"code\":-32600,\"message\":\"bad\"}}");

        assertThat(McpRequestDetector.isMcpResponseSuccess(requestResponse)).isFalse();
    }

    @Test
    void isMcpResponseSuccess_returnsFalseForNonJsonBody() {
        when(requestResponse.response()).thenReturn(response);
        when(response.statusCode()).thenReturn((short) 200);
        when(response.bodyToString()).thenReturn("definitely not json");

        assertThat(McpRequestDetector.isMcpResponseSuccess(requestResponse)).isFalse();
    }

    @Test
    void isMcpResponseSuccess_returnsTrueFor200WithWellFormedJsonRpcResult() {
        when(requestResponse.response()).thenReturn(response);
        when(response.statusCode()).thenReturn((short) 200);
        when(response.bodyToString()).thenReturn(
                "{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{\"tools\":[]}}");

        assertThat(McpRequestDetector.isMcpResponseSuccess(requestResponse)).isTrue();
    }

    // ---------------------------------------------------------------------------------------
    // responseShapesMatch — compares JSON-RPC result envelopes by their structural keys
    // (sorted tool/resource/prompt names, init protocol/serverInfo/capabilities fingerprint,
    // generic top-level field-name set). Lock in tolerance to id / timestamp / order
    // variation that would otherwise cause false negatives on legitimate identical-shape
    // probes.
    // ---------------------------------------------------------------------------------------

    @Test
    void responseShapesMatch_returnsFalseWhenBaselineNotSuccessful() {
        HttpRequestResponse failed = mockResponse((short) 200,
                "{\"jsonrpc\":\"2.0\",\"id\":1,\"error\":{\"code\":-32600,\"message\":\"bad\"}}");
        HttpRequestResponse probe = mockResponse((short) 200,
                "{\"jsonrpc\":\"2.0\",\"id\":2,\"result\":{\"tools\":[]}}");

        assertThat(McpRequestDetector.responseShapesMatch(failed, probe)).isFalse();
    }

    @Test
    void responseShapesMatch_returnsFalseWhenProbeNotSuccessful() {
        HttpRequestResponse baseline = mockResponse((short) 200,
                "{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{\"tools\":[]}}");
        HttpRequestResponse failed = mockResponse((short) 403, "");

        assertThat(McpRequestDetector.responseShapesMatch(baseline, failed)).isFalse();
    }

    @Test
    void responseShapesMatch_matchesIdenticalToolsListBodies() {
        HttpRequestResponse baseline = mockResponse((short) 200,
                "{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{\"tools\":[{\"name\":\"a\"},{\"name\":\"b\"}]}}");
        HttpRequestResponse probe = mockResponse((short) 200,
                "{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{\"tools\":[{\"name\":\"a\"},{\"name\":\"b\"}]}}");

        assertThat(McpRequestDetector.responseShapesMatch(baseline, probe)).isTrue();
    }

    @Test
    void responseShapesMatch_isToleratantToJsonRpcIdDifference() {
        // Different JSON-RPC ids — same shape. Must still match (a probe always has a
        // different id than the baseline).
        HttpRequestResponse baseline = mockResponse((short) 200,
                "{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{\"tools\":[{\"name\":\"a\"}]}}");
        HttpRequestResponse probe = mockResponse((short) 200,
                "{\"jsonrpc\":\"2.0\",\"id\":99,\"result\":{\"tools\":[{\"name\":\"a\"}]}}");

        assertThat(McpRequestDetector.responseShapesMatch(baseline, probe)).isTrue();
    }

    @Test
    void responseShapesMatch_isOrderIndependentForToolsArray() {
        // tools returned in different order — server may iterate a HashMap. Must still
        // be treated as equivalent.
        HttpRequestResponse baseline = mockResponse((short) 200,
                "{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{\"tools\":[{\"name\":\"a\"},{\"name\":\"b\"}]}}");
        HttpRequestResponse probe = mockResponse((short) 200,
                "{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{\"tools\":[{\"name\":\"b\"},{\"name\":\"a\"}]}}");

        assertThat(McpRequestDetector.responseShapesMatch(baseline, probe)).isTrue();
    }

    @Test
    void responseShapesMatch_isOrderIndependentForResourcesArray() {
        HttpRequestResponse baseline = mockResponse((short) 200,
                "{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{\"resources\":[{\"uri\":\"file:///a\"},{\"uri\":\"file:///b\"}]}}");
        HttpRequestResponse probe = mockResponse((short) 200,
                "{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{\"resources\":[{\"uri\":\"file:///b\"},{\"uri\":\"file:///a\"}]}}");

        assertThat(McpRequestDetector.responseShapesMatch(baseline, probe)).isTrue();
    }

    @Test
    void responseShapesMatch_isOrderIndependentForPromptsArray() {
        HttpRequestResponse baseline = mockResponse((short) 200,
                "{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{\"prompts\":[{\"name\":\"a\"},{\"name\":\"b\"}]}}");
        HttpRequestResponse probe = mockResponse((short) 200,
                "{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{\"prompts\":[{\"name\":\"b\"},{\"name\":\"a\"}]}}");

        assertThat(McpRequestDetector.responseShapesMatch(baseline, probe)).isTrue();
    }

    @Test
    void responseShapesMatch_rejectsDifferentToolSets() {
        HttpRequestResponse baseline = mockResponse((short) 200,
                "{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{\"tools\":[{\"name\":\"a\"},{\"name\":\"b\"},{\"name\":\"c\"}]}}");
        HttpRequestResponse filtered = mockResponse((short) 200,
                "{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{\"tools\":[]}}");

        assertThat(McpRequestDetector.responseShapesMatch(baseline, filtered)).isFalse();
    }

    @Test
    void responseShapesMatch_matchesIdenticalInitializeFingerprint() {
        String body = "{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{"
                + "\"protocolVersion\":\"2025-11-25\","
                + "\"serverInfo\":{\"name\":\"my-server\",\"version\":\"1.0\"},"
                + "\"capabilities\":{\"tools\":{},\"resources\":{}}}}";
        HttpRequestResponse baseline = mockResponse((short) 200, body);
        HttpRequestResponse probe = mockResponse((short) 200, body);

        assertThat(McpRequestDetector.responseShapesMatch(baseline, probe)).isTrue();
    }

    @Test
    void responseShapesMatch_rejectsDifferentProtocolVersion() {
        String baselineBody = "{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{"
                + "\"protocolVersion\":\"2025-11-25\","
                + "\"serverInfo\":{\"name\":\"my-server\"},"
                + "\"capabilities\":{\"tools\":{}}}}";
        String probeBody = "{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{"
                + "\"protocolVersion\":\"2024-06-25\","
                + "\"serverInfo\":{\"name\":\"my-server\"},"
                + "\"capabilities\":{\"tools\":{}}}}";

        assertThat(McpRequestDetector.responseShapesMatch(
                mockResponse((short) 200, baselineBody),
                mockResponse((short) 200, probeBody))).isFalse();
    }

    @Test
    void responseShapesMatch_genericFallbackUsesTopLevelFieldNames() {
        // Generic result envelope (no tools/resources/prompts/protocolVersion). Match
        // by the SET of top-level field names — values themselves can differ (timestamps
        // or other server-time fields are tolerated).
        HttpRequestResponse baseline = mockResponse((short) 200,
                "{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{\"status\":\"ok\",\"timestamp\":\"2026-01-01T00:00:00Z\"}}");
        HttpRequestResponse probe = mockResponse((short) 200,
                "{\"jsonrpc\":\"2.0\",\"id\":2,\"result\":{\"status\":\"ok\",\"timestamp\":\"2026-05-22T12:34:56Z\"}}");

        assertThat(McpRequestDetector.responseShapesMatch(baseline, probe)).isTrue();
    }

    @Test
    void responseShapesMatch_genericFallbackRejectsDifferentFieldNameSet() {
        HttpRequestResponse baseline = mockResponse((short) 200,
                "{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{\"status\":\"ok\"}}");
        HttpRequestResponse probe = mockResponse((short) 200,
                "{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{\"status\":\"ok\",\"warning\":\"extra\"}}");

        assertThat(McpRequestDetector.responseShapesMatch(baseline, probe)).isFalse();
    }

    @Test
    void responseShapesMatch_toolCallResultsWithSameKeysButDifferentContentDiverge() {
        // tools/call result envelopes share top-level keys {content, isError} but carry
        // DIFFERENT content text. Comparing only the key SET would mis-classify these as
        // equal (a false-positive VULNERABLE in the DNS-rebinding check). They must diverge.
        HttpRequestResponse baseline = mockResponse((short) 200,
                "{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{\"content\":[{\"type\":\"text\",\"text\":\"localhost data\"}],\"isError\":false}}");
        HttpRequestResponse probe = mockResponse((short) 200,
                "{\"jsonrpc\":\"2.0\",\"id\":2,\"result\":{\"content\":[{\"type\":\"text\",\"text\":\"access denied for attacker.example\"}],\"isError\":false}}");

        assertThat(McpRequestDetector.responseShapesMatch(baseline, probe)).isFalse();
    }

    @Test
    void responseShapesMatch_toolCallResultsWithSameKeysButDifferentIsErrorDiverge() {
        // Same content text and top-level keys, but isError differs. A rejection that
        // returns isError:true must not be treated as an identical success.
        HttpRequestResponse baseline = mockResponse((short) 200,
                "{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{\"content\":[{\"type\":\"text\",\"text\":\"ok\"}],\"isError\":false}}");
        HttpRequestResponse probe = mockResponse((short) 200,
                "{\"jsonrpc\":\"2.0\",\"id\":2,\"result\":{\"content\":[{\"type\":\"text\",\"text\":\"ok\"}],\"isError\":true}}");

        assertThat(McpRequestDetector.responseShapesMatch(baseline, probe)).isFalse();
    }

    @Test
    void responseShapesMatch_toolCallResultsWithIdenticalContentMatch() {
        // Identical tool-call result content (and isError) — a genuine rebind where the
        // server replays the same answer to the rewritten Host/Origin. Must still match.
        String body = "{\"jsonrpc\":\"2.0\",\"id\":%d,\"result\":{\"content\":[{\"type\":\"text\",\"text\":\"same answer\"}],\"isError\":false}}";
        HttpRequestResponse baseline = mockResponse((short) 200, String.format(body, 1));
        HttpRequestResponse probe = mockResponse((short) 200, String.format(body, 2));

        assertThat(McpRequestDetector.responseShapesMatch(baseline, probe)).isTrue();
    }

    private static HttpRequestResponse mockResponse(short statusCode, String body) {
        HttpRequestResponse rr = org.mockito.Mockito.mock(HttpRequestResponse.class);
        HttpResponse resp = org.mockito.Mockito.mock(HttpResponse.class);
        org.mockito.Mockito.lenient().when(rr.response()).thenReturn(resp);
        org.mockito.Mockito.lenient().when(resp.statusCode()).thenReturn(statusCode);
        org.mockito.Mockito.lenient().when(resp.bodyToString()).thenReturn(body);
        return rr;
    }

    @Test
    void isToolCallSuccess_returnsFalseWhenResultIsErrorTrue() {
        when(requestResponse.response()).thenReturn(response);
        when(response.statusCode()).thenReturn((short) 200);
        when(response.bodyToString()).thenReturn(
                "{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{\"content\":[{\"type\":\"text\",\"text\":\"invalid\"}],\"isError\":true}}");

        assertThat(McpRequestDetector.isToolCallSuccess(requestResponse)).isFalse();
    }

    @Test
    void isToolCallSuccess_returnsFalseWhenTopLevelErrorPresent() {
        when(requestResponse.response()).thenReturn(response);
        when(response.statusCode()).thenReturn((short) 200);
        when(response.bodyToString()).thenReturn(
                "{\"jsonrpc\":\"2.0\",\"id\":1,\"error\":{\"code\":-32602,\"message\":\"bad\"}}");

        assertThat(McpRequestDetector.isToolCallSuccess(requestResponse)).isFalse();
    }

    @Test
    void isToolCallSuccess_returnsFalseWhenResultMissing() {
        when(requestResponse.response()).thenReturn(response);
        when(response.statusCode()).thenReturn((short) 200);
        when(response.bodyToString()).thenReturn("{\"jsonrpc\":\"2.0\",\"id\":1}");

        assertThat(McpRequestDetector.isToolCallSuccess(requestResponse)).isFalse();
    }

    @Test
    void isToolCallSuccess_returnsTrueWhenResultPresentAndNoErrors() {
        when(requestResponse.response()).thenReturn(response);
        when(response.statusCode()).thenReturn((short) 200);
        when(response.bodyToString()).thenReturn(
                "{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{\"content\":[{\"type\":\"text\",\"text\":\"ok\"}]}}");

        assertThat(McpRequestDetector.isToolCallSuccess(requestResponse)).isTrue();
    }

    @Test
    void isToolCallSuccess_returnsFalseOnNon200Status() {
        when(requestResponse.response()).thenReturn(response);
        when(response.statusCode()).thenReturn((short) 401);

        assertThat(McpRequestDetector.isToolCallSuccess(requestResponse)).isFalse();
    }

    @Test
    void isToolCallSuccess_returnsFalseWhenResponseIsNull() {
        when(requestResponse.response()).thenReturn(null);

        assertThat(McpRequestDetector.isToolCallSuccess(requestResponse)).isFalse();
    }

    // ---------------------------------------------------------------------------------------
    // isMethodRecognised — used by JsonRpcMethodProbeRunner to classify a 200-OK response
    // with no JSON-RPC error envelope. Looser than isToolCallSuccess: any presence of a
    // `result` key (including null/tool-error-shaped) means the server dispatched the
    // method. The only error code that indicates non-recognition is -32601.
    // ---------------------------------------------------------------------------------------

    @Test
    void isMethodRecognised_returnsTrueForResultNull() {
        when(requestResponse.response()).thenReturn(response);
        when(response.statusCode()).thenReturn((short) 200);
        when(response.bodyToString()).thenReturn("{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":null}");

        assertThat(McpRequestDetector.isMethodRecognised(requestResponse)).isTrue();
    }

    @Test
    void isMethodRecognised_returnsTrueForToolErrorEnvelope() {
        when(requestResponse.response()).thenReturn(response);
        when(response.statusCode()).thenReturn((short) 200);
        when(response.bodyToString()).thenReturn(
                "{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{\"isError\":true,\"content\":[]}}");

        assertThat(McpRequestDetector.isMethodRecognised(requestResponse)).isTrue();
    }

    @Test
    void isMethodRecognised_returnsTrueForOpaqueResultObject() {
        when(requestResponse.response()).thenReturn(response);
        when(response.statusCode()).thenReturn((short) 200);
        when(response.bodyToString()).thenReturn(
                "{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{\"foo\":\"bar\"}}");

        assertThat(McpRequestDetector.isMethodRecognised(requestResponse)).isTrue();
    }

    @Test
    void isMethodRecognised_returnsFalseForMethodNotFound() {
        when(requestResponse.response()).thenReturn(response);
        when(response.statusCode()).thenReturn((short) 200);
        when(response.bodyToString()).thenReturn(
                "{\"jsonrpc\":\"2.0\",\"id\":1,\"error\":{\"code\":-32601,\"message\":\"Method not found\"}}");

        assertThat(McpRequestDetector.isMethodRecognised(requestResponse)).isFalse();
    }

    @Test
    void isMethodRecognised_returnsTrueForInvalidParams() {
        when(requestResponse.response()).thenReturn(response);
        when(response.statusCode()).thenReturn((short) 200);
        when(response.bodyToString()).thenReturn(
                "{\"jsonrpc\":\"2.0\",\"id\":1,\"error\":{\"code\":-32602,\"message\":\"Invalid params\"}}");

        assertThat(McpRequestDetector.isMethodRecognised(requestResponse)).isTrue();
    }

    @Test
    void isMethodRecognised_returnsFalseForEmptyEnvelope() {
        when(requestResponse.response()).thenReturn(response);
        when(response.statusCode()).thenReturn((short) 200);
        when(response.bodyToString()).thenReturn("{\"jsonrpc\":\"2.0\",\"id\":1}");

        assertThat(McpRequestDetector.isMethodRecognised(requestResponse)).isFalse();
    }

    @Test
    void isMethodRecognised_returnsFalseForNon200Status() {
        when(requestResponse.response()).thenReturn(response);
        when(response.statusCode()).thenReturn((short) 500);

        assertThat(McpRequestDetector.isMethodRecognised(requestResponse)).isFalse();
    }

    @Test
    void isMethodRecognised_returnsFalseForNullResponse() {
        when(requestResponse.response()).thenReturn(null);

        assertThat(McpRequestDetector.isMethodRecognised(requestResponse)).isFalse();
    }

    @Test
    void extractErrorCodeReturnsCodeFromPlainJsonRpcError() {
        when(requestResponse.response()).thenReturn(response);
        when(response.bodyToString())
                .thenReturn("{\"jsonrpc\":\"2.0\",\"error\":{\"code\":-32601,\"message\":\"x\"}}");

        assertThat(McpRequestDetector.extractErrorCode(requestResponse)).contains(-32601);
    }

    @Test
    void extractErrorCodeUnwrapsSseFramedError() {
        when(requestResponse.response()).thenReturn(response);
        when(response.headerValue("Content-Type")).thenReturn("text/event-stream");
        when(response.bodyToString()).thenReturn(
                "event: message\ndata: {\"jsonrpc\":\"2.0\",\"error\":{\"code\":-32602,\"message\":\"x\"}}\n\n");

        assertThat(McpRequestDetector.extractErrorCode(requestResponse)).contains(-32602);
    }

    @Test
    void extractErrorCodeReturnsEmptyForResultResponse() {
        when(requestResponse.response()).thenReturn(response);
        when(response.bodyToString()).thenReturn("{\"jsonrpc\":\"2.0\",\"result\":{}}");

        assertThat(McpRequestDetector.extractErrorCode(requestResponse)).isEmpty();
    }

    @Test
    void extractErrorCodeReturnsEmptyWhenResponseIsNull() {
        when(requestResponse.response()).thenReturn(null);

        assertThat(McpRequestDetector.extractErrorCode(requestResponse)).isEmpty();
    }

    @Test
    void errorCodeFromBodyReturnsEmptyForNonIntegralCode() {
        assertThat(McpRequestDetector.errorCodeFromBody(
                "{\"error\":{\"code\":\"oops\"}}")).isEmpty();
    }

    // ---------------------------------------------------------------------------------------
    // classifyDiscoveryResponse — defense-in-depth filter used by the passive scanner. A
    // response counts as a discovery payload only when (a) the request was a well-formed
    // POST application/json JSON-RPC 2.0 envelope, (b) the request method is one of the
    // four discovery methods, and (c) the response is a 200 with a JSON-RPC result envelope
    // that contains the expected top-level field. Anything else → OTHER.
    // ---------------------------------------------------------------------------------------

    @Test
    void classifyDiscoveryResponse_returnsToolsListForMatchingPair() {
        HttpRequestResponse rr = discoveryPair("tools/list",
                "{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{\"tools\":[]}}");

        assertThat(McpRequestDetector.classifyDiscoveryResponse(rr))
                .isEqualTo(DiscoveryResponseKind.TOOLS_LIST);
    }

    @Test
    void classifyDiscoveryResponse_returnsResourcesListForMatchingPair() {
        HttpRequestResponse rr = discoveryPair("resources/list",
                "{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{\"resources\":[]}}");

        assertThat(McpRequestDetector.classifyDiscoveryResponse(rr))
                .isEqualTo(DiscoveryResponseKind.RESOURCES_LIST);
    }

    @Test
    void classifyDiscoveryResponse_returnsPromptsListForMatchingPair() {
        HttpRequestResponse rr = discoveryPair("prompts/list",
                "{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{\"prompts\":[]}}");

        assertThat(McpRequestDetector.classifyDiscoveryResponse(rr))
                .isEqualTo(DiscoveryResponseKind.PROMPTS_LIST);
    }

    @Test
    void classifyDiscoveryResponse_returnsInitializeForMatchingPair() {
        HttpRequestResponse rr = discoveryPair("initialize",
                "{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{"
                        + "\"protocolVersion\":\"2025-11-25\","
                        + "\"serverInfo\":{\"name\":\"x\"},\"capabilities\":{}}}");

        assertThat(McpRequestDetector.classifyDiscoveryResponse(rr))
                .isEqualTo(DiscoveryResponseKind.INITIALIZE);
    }

    @Test
    void classifyDiscoveryResponse_returnsOtherForToolsCall() {
        HttpRequestResponse rr = discoveryPair("tools/call",
                "{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{\"content\":[]}}");

        assertThat(McpRequestDetector.classifyDiscoveryResponse(rr))
                .isEqualTo(DiscoveryResponseKind.OTHER);
    }

    @Test
    void classifyDiscoveryResponse_returnsOtherForPingMethod() {
        HttpRequestResponse rr = discoveryPair("ping",
                "{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{}}");

        assertThat(McpRequestDetector.classifyDiscoveryResponse(rr))
                .isEqualTo(DiscoveryResponseKind.OTHER);
    }

    @Test
    void classifyDiscoveryResponse_returnsOtherForResourceTemplatesList() {
        HttpRequestResponse rr = discoveryPair("resources/templates/list",
                "{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{\"resourceTemplates\":[]}}");

        assertThat(McpRequestDetector.classifyDiscoveryResponse(rr))
                .isEqualTo(DiscoveryResponseKind.OTHER);
    }

    @Test
    void classifyDiscoveryResponse_returnsOtherWhenRequestNotJsonRpc() {
        HttpRequestResponse rr = buildPair("POST", "application/json",
                "{\"data\":\"not jsonrpc\"}",
                "{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{\"tools\":[]}}");

        assertThat(McpRequestDetector.classifyDiscoveryResponse(rr))
                .isEqualTo(DiscoveryResponseKind.OTHER);
    }

    @Test
    void classifyDiscoveryResponse_returnsOtherWhenRequestMissingId() {
        // JSON-RPC 2.0 requests require id (or be a notification). A discovery-method
        // notification with no id is malformed for our purposes and should not classify
        // as a discovery response.
        HttpRequestResponse rr = buildPair("POST", "application/json",
                "{\"jsonrpc\":\"2.0\",\"method\":\"tools/list\"}",
                "{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{\"tools\":[]}}");

        assertThat(McpRequestDetector.classifyDiscoveryResponse(rr))
                .isEqualTo(DiscoveryResponseKind.OTHER);
    }

    @Test
    void classifyDiscoveryResponse_returnsOtherWhenRequestContentTypeNotJson() {
        HttpRequestResponse rr = buildPair("POST", "text/plain",
                "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/list\"}",
                "{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{\"tools\":[]}}");

        assertThat(McpRequestDetector.classifyDiscoveryResponse(rr))
                .isEqualTo(DiscoveryResponseKind.OTHER);
    }

    @Test
    void classifyDiscoveryResponse_returnsOtherWhenResponseIsError() {
        HttpRequestResponse rr = discoveryPair("tools/list",
                "{\"jsonrpc\":\"2.0\",\"id\":1,\"error\":{\"code\":-32601,\"message\":\"bad\"}}");

        assertThat(McpRequestDetector.classifyDiscoveryResponse(rr))
                .isEqualTo(DiscoveryResponseKind.OTHER);
    }

    @Test
    void classifyDiscoveryResponse_returnsOtherWhenResponseMissingExpectedShape() {
        // Method says tools/list but result has no "tools" array — server malfunction
        // or unrelated. Don't classify as a discovery response.
        HttpRequestResponse rr = discoveryPair("tools/list",
                "{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{\"unexpected\":true}}");

        assertThat(McpRequestDetector.classifyDiscoveryResponse(rr))
                .isEqualTo(DiscoveryResponseKind.OTHER);
    }

    @Test
    void classifyDiscoveryResponse_returnsOtherWhenResponseBodyNotJson() {
        HttpRequestResponse rr = buildPair("POST", "application/json",
                "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/list\"}",
                "<html>oops</html>");

        assertThat(McpRequestDetector.classifyDiscoveryResponse(rr))
                .isEqualTo(DiscoveryResponseKind.OTHER);
    }

    @Test
    void classifyDiscoveryResponse_returnsOtherWhenResponseStatusNon200() {
        HttpRequestResponse rr = org.mockito.Mockito.mock(HttpRequestResponse.class);
        HttpRequest req = org.mockito.Mockito.mock(HttpRequest.class);
        HttpResponse resp = org.mockito.Mockito.mock(HttpResponse.class);
        org.mockito.Mockito.lenient().when(rr.request()).thenReturn(req);
        org.mockito.Mockito.lenient().when(rr.response()).thenReturn(resp);
        org.mockito.Mockito.lenient().when(req.method()).thenReturn("POST");
        org.mockito.Mockito.lenient().when(req.bodyToString()).thenReturn(
                "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/list\"}");
        org.mockito.Mockito.lenient().when(req.headerValue("Content-Type"))
                .thenReturn("application/json");
        org.mockito.Mockito.lenient().when(resp.statusCode()).thenReturn((short) 401);

        assertThat(McpRequestDetector.classifyDiscoveryResponse(rr))
                .isEqualTo(DiscoveryResponseKind.OTHER);
    }

    @Test
    void classifyDiscoveryResponse_returnsOtherWhenRequestMethodNotPost() {
        HttpRequestResponse rr = buildPair("GET", "application/json",
                "",
                "{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{\"tools\":[]}}");

        assertThat(McpRequestDetector.classifyDiscoveryResponse(rr))
                .isEqualTo(DiscoveryResponseKind.OTHER);
    }

    @Test
    void classifyDiscoveryResponse_returnsOtherWhenResponseAbsent() {
        HttpRequestResponse rr = org.mockito.Mockito.mock(HttpRequestResponse.class);
        HttpRequest req = org.mockito.Mockito.mock(HttpRequest.class);
        org.mockito.Mockito.lenient().when(rr.request()).thenReturn(req);
        org.mockito.Mockito.lenient().when(req.method()).thenReturn("POST");
        org.mockito.Mockito.lenient().when(req.bodyToString()).thenReturn(
                "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/list\"}");
        org.mockito.Mockito.lenient().when(req.headerValue("Content-Type"))
                .thenReturn("application/json");
        org.mockito.Mockito.lenient().when(rr.response()).thenReturn(null);

        assertThat(McpRequestDetector.classifyDiscoveryResponse(rr))
                .isEqualTo(DiscoveryResponseKind.OTHER);
    }

    // ---------------------------------------------------------------------------------------
    // classifyResponseContent — runtime-output filter used by the response-body content
    // scanner. Disjoint from classifyDiscoveryResponse by method set (tools/call,
    // resources/read, prompts/get) so the two scanners never double-fire on one exchange.
    // ---------------------------------------------------------------------------------------

    @Test
    void classifyResponseContent_returnsToolCallForMatchingPair() {
        HttpRequestResponse rr = responsePair("tools/call",
                "{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{\"content\":[{\"type\":\"text\",\"text\":\"ok\"}]}}");

        assertThat(McpRequestDetector.classifyResponseContent(rr))
                .isEqualTo(ResponseContentKind.TOOL_CALL);
    }

    @Test
    void classifyResponseContent_returnsResourceReadForMatchingPair() {
        HttpRequestResponse rr = responsePair("resources/read",
                "{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{\"contents\":[{\"text\":\"ok\"}]}}");

        assertThat(McpRequestDetector.classifyResponseContent(rr))
                .isEqualTo(ResponseContentKind.RESOURCE_READ);
    }

    @Test
    void classifyResponseContent_returnsPromptGetForMatchingPair() {
        HttpRequestResponse rr = responsePair("prompts/get",
                "{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{\"messages\":[]}}");

        assertThat(McpRequestDetector.classifyResponseContent(rr))
                .isEqualTo(ResponseContentKind.PROMPT_GET);
    }

    @Test
    void classifyResponseContent_classifiesSseFramedToolCall() {
        HttpRequestResponse rr = responsePairWithResponseContentType("tools/call",
                "text/event-stream",
                "event: message\ndata: {\"jsonrpc\":\"2.0\",\"id\":1,"
                        + "\"result\":{\"content\":[{\"type\":\"text\",\"text\":\"ok\"}]}}\n\n");

        assertThat(McpRequestDetector.classifyResponseContent(rr))
                .isEqualTo(ResponseContentKind.TOOL_CALL);
    }

    @Test
    void classifyResponseContent_returnsOtherForDiscoveryMethod() {
        HttpRequestResponse rr = responsePair("tools/list",
                "{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{\"tools\":[]}}");

        assertThat(McpRequestDetector.classifyResponseContent(rr))
                .isEqualTo(ResponseContentKind.OTHER);
    }

    @Test
    void classifyResponseContent_returnsOtherForError() {
        HttpRequestResponse rr = responsePair("tools/call",
                "{\"jsonrpc\":\"2.0\",\"id\":1,\"error\":{\"code\":-32601,\"message\":\"bad\"}}");

        assertThat(McpRequestDetector.classifyResponseContent(rr))
                .isEqualTo(ResponseContentKind.OTHER);
    }

    @Test
    void classifyResponseContent_returnsOtherForNon200() {
        HttpRequestResponse rr = org.mockito.Mockito.mock(HttpRequestResponse.class);
        HttpRequest req = org.mockito.Mockito.mock(HttpRequest.class);
        HttpResponse resp = org.mockito.Mockito.mock(HttpResponse.class);
        org.mockito.Mockito.lenient().when(rr.request()).thenReturn(req);
        org.mockito.Mockito.lenient().when(rr.response()).thenReturn(resp);
        org.mockito.Mockito.lenient().when(req.method()).thenReturn("POST");
        org.mockito.Mockito.lenient().when(req.bodyToString()).thenReturn(
                "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/call\"}");
        org.mockito.Mockito.lenient().when(req.headerValue("Content-Type"))
                .thenReturn("application/json");
        org.mockito.Mockito.lenient().when(resp.statusCode()).thenReturn((short) 401);

        assertThat(McpRequestDetector.classifyResponseContent(rr))
                .isEqualTo(ResponseContentKind.OTHER);
    }

    @Test
    void classifyResponseContent_returnsOtherForNonPost() {
        HttpRequestResponse rr = buildPair("GET", "application/json", "",
                "{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{\"content\":[]}}");

        assertThat(McpRequestDetector.classifyResponseContent(rr))
                .isEqualTo(ResponseContentKind.OTHER);
    }

    @Test
    void classifyResponseContent_returnsOtherForNonJsonRequestContentType() {
        HttpRequestResponse rr = buildPair("POST", "text/plain",
                "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/call\"}",
                "{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{\"content\":[]}}");

        assertThat(McpRequestDetector.classifyResponseContent(rr))
                .isEqualTo(ResponseContentKind.OTHER);
    }

    private static HttpRequestResponse responsePair(String method, String responseBody) {
        String requestBody = "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"" + method + "\"}";
        return buildPair("POST", "application/json", requestBody, responseBody);
    }

    private static HttpRequestResponse responsePairWithResponseContentType(String method,
                                                                           String responseContentType,
                                                                           String responseBody) {
        HttpRequestResponse rr = responsePair(method, responseBody);
        org.mockito.Mockito.lenient().when(rr.response().headerValue("Content-Type"))
                .thenReturn(responseContentType);
        return rr;
    }

    private static HttpRequestResponse discoveryPair(String method, String responseBody) {
        String requestBody = "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"" + method + "\"}";
        return buildPair("POST", "application/json", requestBody, responseBody);
    }

    private static HttpRequestResponse buildPair(String httpMethod, String requestContentType,
                                                 String requestBody, String responseBody) {
        HttpRequestResponse rr = org.mockito.Mockito.mock(HttpRequestResponse.class);
        HttpRequest req = org.mockito.Mockito.mock(HttpRequest.class);
        HttpResponse resp = org.mockito.Mockito.mock(HttpResponse.class);
        org.mockito.Mockito.lenient().when(rr.request()).thenReturn(req);
        org.mockito.Mockito.lenient().when(rr.response()).thenReturn(resp);
        org.mockito.Mockito.lenient().when(req.method()).thenReturn(httpMethod);
        org.mockito.Mockito.lenient().when(req.bodyToString()).thenReturn(requestBody);
        org.mockito.Mockito.lenient().when(req.headerValue("Content-Type"))
                .thenReturn(requestContentType);
        org.mockito.Mockito.lenient().when(resp.statusCode()).thenReturn((short) 200);
        org.mockito.Mockito.lenient().when(resp.bodyToString()).thenReturn(responseBody);
        return rr;
    }

    private void stubRequest(String method, String body) {
        when(requestResponse.request()).thenReturn(request);
        when(request.method()).thenReturn(method);
        if ("POST".equalsIgnoreCase(method)) {
            when(request.bodyToString()).thenReturn(body);
        }
    }
}
