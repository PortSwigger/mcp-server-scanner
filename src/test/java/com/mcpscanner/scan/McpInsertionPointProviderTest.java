package com.mcpscanner.scan;

import burp.api.montoya.core.ByteArray;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.scanner.audit.insertionpoint.AuditInsertionPoint;
import burp.api.montoya.scanner.audit.insertionpoint.AuditInsertionPointType;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.mcpscanner.testutil.MontoyaTestFactory;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class McpInsertionPointProviderTest {

    private static final ObjectMapper MAPPER = new ObjectMapper();

    @Mock
    private HttpRequestResponse requestResponse;

    @Mock
    private HttpRequest request;

    private McpInsertionPointProvider provider;

    @BeforeAll
    static void installFactory() {
        MontoyaTestFactory.install();
    }

    @BeforeEach
    void setUp() {
        provider = new McpInsertionPointProvider();
    }

    @Test
    void returnsEmptyListForNonPostRequest() {
        stubRequest("GET", "");

        List<AuditInsertionPoint> result = provider.provideInsertionPoints(requestResponse);

        assertThat(result).isEmpty();
    }

    @Test
    void returnsEmptyListForNonMcpRequest() {
        stubRequest("POST", "{\"method\":\"someOtherMethod\"}");

        List<AuditInsertionPoint> result = provider.provideInsertionPoints(requestResponse);

        assertThat(result).isEmpty();
    }

    @Test
    void returnsEmptyListForToolsListRequest() {
        stubRequest("POST", "{\"jsonrpc\":\"2.0\",\"method\":\"tools/list\"}");

        List<AuditInsertionPoint> result = provider.provideInsertionPoints(requestResponse);

        assertThat(result).isEmpty();
    }

    @Test
    void returnsInsertionPointForStringArgument() {
        String body = "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/call\","
                + "\"params\":{\"name\":\"echo\",\"arguments\":{\"msg\":\"hello\"}}}";
        stubRequest("POST", body);

        List<AuditInsertionPoint> result = provider.provideInsertionPoints(requestResponse);

        assertThat(result).hasSize(1);
        assertThat(result.get(0).name()).isEqualTo("MCP arg: msg");
        assertThat(result.get(0).type()).isEqualTo(AuditInsertionPointType.PARAM_JSON);
    }

    @Test
    void returnsJsonValueInsertionPointForIntegerArguments() {
        String body = "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/call\","
                + "\"params\":{\"name\":\"calc\",\"arguments\":{\"count\":42}}}";
        stubRequest("POST", body);

        List<AuditInsertionPoint> result = provider.provideInsertionPoints(requestResponse);

        assertThat(result).hasSize(1);
        assertThat(result.get(0).name()).isEqualTo("MCP arg: count");
        assertThat(result.get(0).type()).isEqualTo(AuditInsertionPointType.PARAM_JSON);
    }

    @Test
    void returnsInsertionPointsForAllPrimitiveArgumentTypes() {
        String body = "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/call\","
                + "\"params\":{\"name\":\"multi\",\"arguments\":{\"active\":true,\"count\":1,\"name\":\"test\"}}}";
        stubRequest("POST", body);

        List<AuditInsertionPoint> result = provider.provideInsertionPoints(requestResponse);

        assertThat(result).hasSize(3);
        assertThat(result).allSatisfy(point ->
                assertThat(point.type()).isEqualTo(AuditInsertionPointType.PARAM_JSON));
    }

    @Test
    void insertionPointNamesStartWithMcpArg() {
        String body = "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/call\","
                + "\"params\":{\"name\":\"multi\",\"arguments\":{\"alpha\":\"a\",\"beta\":2}}}";
        stubRequest("POST", body);

        List<AuditInsertionPoint> result = provider.provideInsertionPoints(requestResponse);

        assertThat(result).allSatisfy(point ->
                assertThat(point.name()).startsWith("MCP arg: "));
    }

    @Test
    void returnsEmptyListForToolsCallWithEmptyArguments() {
        String body = "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/call\","
                + "\"params\":{\"name\":\"noop\",\"arguments\":{}}}";
        stubRequest("POST", body);

        List<AuditInsertionPoint> result = provider.provideInsertionPoints(requestResponse);

        assertThat(result).isEmpty();
    }

    @Test
    void returnsEmptyListForToolsCallWithNoArguments() {
        String body = "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/call\","
                + "\"params\":{\"name\":\"noop\"}}";
        stubRequest("POST", body);

        List<AuditInsertionPoint> result = provider.provideInsertionPoints(requestResponse);

        assertThat(result).isEmpty();
    }

    @Test
    void returnsEmptyListForMalformedJsonBody() {
        stubRequest("POST", "{\"method\":\"tools/call\", invalid json}}");

        List<AuditInsertionPoint> result = provider.provideInsertionPoints(requestResponse);

        assertThat(result).isEmpty();
    }

    @Test
    void skipsArrayAndObjectArguments() {
        String body = "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/call\","
                + "\"params\":{\"name\":\"complex\",\"arguments\":{\"config\":{},\"items\":[1,2],\"label\":\"test\"}}}";
        stubRequest("POST", body);

        List<AuditInsertionPoint> result = provider.provideInsertionPoints(requestResponse);

        assertThat(result).hasSize(1);
        assertThat(result.get(0).name()).isEqualTo("MCP arg: label");
    }

    @Test
    void handlesPrettyPrintedJson() {
        String body = "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/call\","
                + "\"params\":{\"name\":\"echo\",\"arguments\" : {\"msg\":\"hello\"}}}";
        stubRequest("POST", body);

        List<AuditInsertionPoint> result = provider.provideInsertionPoints(requestResponse);

        assertThat(result).hasSize(1);
        assertThat(result.get(0).name()).isEqualTo("MCP arg: msg");
    }

    @Test
    void returnsEmptyListForNonJsonBodyContainingToolsCall() {
        stubRequest("POST", "This is not JSON but contains tools/call");

        List<AuditInsertionPoint> result = provider.provideInsertionPoints(requestResponse);

        assertThat(result).isEmpty();
    }

    @Test
    void stringArgumentInsertionPointHandlesAttackPayloadSafely() throws Exception {
        String body = "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/call\","
                + "\"params\":{\"name\":\"echo\",\"arguments\":{\"msg\":\"hello\"}}}";
        stubRequestWithCapturedBody("POST", body);

        List<AuditInsertionPoint> result = provider.provideInsertionPoints(requestResponse);

        assertThat(result).hasSize(1);
        result.get(0).buildHttpRequestWithPayload(ByteArray.byteArray("evil\"\\\n"));

        String newBody = capturedBody();
        JsonNode root = MAPPER.readTree(newBody);
        assertThat(root.at("/params/arguments/msg").asText()).isEqualTo("evil\"\\\n");
    }

    @Test
    void numberArgumentInsertionPointAcceptsRawNumberPayload() throws Exception {
        String body = "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/call\","
                + "\"params\":{\"name\":\"calc\",\"arguments\":{\"count\":42}}}";
        stubRequestWithCapturedBody("POST", body);

        List<AuditInsertionPoint> result = provider.provideInsertionPoints(requestResponse);

        result.get(0).buildHttpRequestWithPayload(ByteArray.byteArray("9001"));

        JsonNode root = MAPPER.readTree(capturedBody());
        assertThat(root.at("/params/arguments/count").asLong()).isEqualTo(9001L);
    }

    @Test
    void numberArgumentInsertionPointWrapsTextPayloadAsString() throws Exception {
        String body = "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/call\","
                + "\"params\":{\"name\":\"calc\",\"arguments\":{\"count\":42}}}";
        stubRequestWithCapturedBody("POST", body);

        List<AuditInsertionPoint> result = provider.provideInsertionPoints(requestResponse);

        result.get(0).buildHttpRequestWithPayload(ByteArray.byteArray("attack\"\\"));

        JsonNode root = MAPPER.readTree(capturedBody());
        assertThat(root.at("/params/arguments/count").asText()).isEqualTo("attack\"\\");
    }

    @Test
    void booleanArgumentInsertionPointAcceptsBooleanPayload() throws Exception {
        String body = "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/call\","
                + "\"params\":{\"name\":\"toggle\",\"arguments\":{\"flag\":true}}}";
        stubRequestWithCapturedBody("POST", body);

        List<AuditInsertionPoint> result = provider.provideInsertionPoints(requestResponse);

        result.get(0).buildHttpRequestWithPayload(ByteArray.byteArray("false"));

        JsonNode root = MAPPER.readTree(capturedBody());
        assertThat(root.at("/params/arguments/flag").asBoolean()).isFalse();
    }

    @Test
    void argumentNameWithEmbeddedQuoteResolvesAndAcceptsPayload() throws Exception {
        String body = "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/call\","
                + "\"params\":{\"name\":\"echo\",\"arguments\":{\"a\\\"b\":\"plain\"}}}";
        stubRequestWithCapturedBody("POST", body);

        List<AuditInsertionPoint> result = provider.provideInsertionPoints(requestResponse);

        assertThat(result).hasSize(1);
        assertThat(result.get(0).name()).isEqualTo("MCP arg: a\"b");

        result.get(0).buildHttpRequestWithPayload(ByteArray.byteArray("ok"));

        JsonNode root = MAPPER.readTree(capturedBody());
        assertThat(root.at("/params/arguments/a\"b").asText()).isEqualTo("ok");
    }

    @Test
    void returnsUriInsertionPointForResourcesReadRequest() {
        String body = "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"resources/read\","
                + "\"params\":{\"uri\":\"file:///etc/passwd\"}}";
        stubRequest("POST", body);

        List<AuditInsertionPoint> result = provider.provideInsertionPoints(requestResponse);

        assertThat(result).hasSize(1);
        assertThat(result.get(0).name()).isEqualTo("MCP arg: uri");
        assertThat(result.get(0).baseValue()).isEqualTo("file:///etc/passwd");
    }

    @Test
    void resourcesReadUriInsertionPointReplacesValueOnPayload() throws Exception {
        String body = "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"resources/read\","
                + "\"params\":{\"uri\":\"file:///etc/passwd\"}}";
        stubRequestWithCapturedBody("POST", body);

        List<AuditInsertionPoint> result = provider.provideInsertionPoints(requestResponse);

        result.get(0).buildHttpRequestWithPayload(ByteArray.byteArray("file:///../../escape"));

        JsonNode root = MAPPER.readTree(capturedBody());
        assertThat(root.at("/params/uri").asText()).isEqualTo("file:///../../escape");
    }

    @Test
    void returnsEmptyListForResourcesReadWithoutUriField() {
        String body = "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"resources/read\","
                + "\"params\":{\"name\":\"foo\"}}";
        stubRequest("POST", body);

        assertThat(provider.provideInsertionPoints(requestResponse)).isEmpty();
    }

    @Test
    void returnsInsertionPointsForPromptsGetArguments() {
        String body = "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"prompts/get\","
                + "\"params\":{\"name\":\"summarize\",\"arguments\":{\"topic\":\"weather\",\"style\":\"brief\"}}}";
        stubRequest("POST", body);

        List<AuditInsertionPoint> result = provider.provideInsertionPoints(requestResponse);

        assertThat(result).hasSize(2);
        assertThat(result).extracting(AuditInsertionPoint::name)
                .containsExactlyInAnyOrder("MCP arg: topic", "MCP arg: style");
    }

    @Test
    void promptsGetInsertionPointReplacesArgumentOnPayload() throws Exception {
        String body = "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"prompts/get\","
                + "\"params\":{\"name\":\"summarize\",\"arguments\":{\"topic\":\"weather\"}}}";
        stubRequestWithCapturedBody("POST", body);

        List<AuditInsertionPoint> result = provider.provideInsertionPoints(requestResponse);

        result.get(0).buildHttpRequestWithPayload(ByteArray.byteArray("payload"));

        JsonNode root = MAPPER.readTree(capturedBody());
        assertThat(root.at("/params/arguments/topic").asText()).isEqualTo("payload");
    }

    @Test
    void returnsEmptyListForUnsupportedMcpMethod() {
        String body = "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"resources/list\",\"params\":{}}";
        stubRequest("POST", body);

        assertThat(provider.provideInsertionPoints(requestResponse)).isEmpty();
    }

    private String capturedBody() {
        ArgumentCaptor<String> captor = ArgumentCaptor.forClass(String.class);
        verify(request).withBody(captor.capture());
        return captor.getValue();
    }

    private void stubRequest(String method, String body) {
        when(requestResponse.request()).thenReturn(request);
        when(request.method()).thenReturn(method);
        if ("POST".equalsIgnoreCase(method) && !body.isEmpty()) {
            when(request.bodyToString()).thenReturn(body);
        }
    }

    private void stubRequestWithCapturedBody(String method, String body) {
        stubRequest(method, body);
        lenient().when(request.withBody(anyString())).thenReturn(mock(HttpRequest.class));
    }
}
