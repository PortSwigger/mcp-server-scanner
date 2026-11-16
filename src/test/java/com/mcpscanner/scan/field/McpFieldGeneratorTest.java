package com.mcpscanner.scan.field;

import burp.api.montoya.core.ByteArray;
import burp.api.montoya.core.Range;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.scanner.audit.insertionpoint.AuditInsertionPoint;
import burp.api.montoya.scanner.audit.insertionpoint.AuditInsertionPointType;
import com.mcpscanner.mcp.BurpNativeJsonRpcFields;
import com.mcpscanner.scan.ArgumentPath;
import com.mcpscanner.testutil.MontoyaTestFactory;
import com.mcpscanner.testutil.RawHttpRequestStub;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

class McpFieldGeneratorTest {

    private static final String TOOL_CALL = "{\"jsonrpc\":\"2.0\",\"id\":3,\"method\":\"tools/call\",\"params\":"
            + "{\"name\":\"fetch\",\"arguments\":{\"url\":\"http://a\",\"retries\":2,\"verbose\":false,"
            + "\"opts\":{\"tags\":[\"x\"]},\"none\":null,\"empty\":{}},\"_meta\":{\"progressToken\":\"p1\"}}}";

    private final McpFieldGenerator withHeaders = new McpFieldGenerator(() -> true);
    private final McpFieldGenerator withoutHeaders = new McpFieldGenerator(() -> false);
    private final McpFieldGenerator besideBurpNativeFields = new McpFieldGenerator(() -> true,
            new TemplateExpansionRegistry(), BurpNativeJsonRpcFields.PRESENT);

    @BeforeEach
    void installMontoya() {
        MontoyaTestFactory.install();
    }

    @Test
    void everyParamsLeafBecomesAJsonInsertionPoint() {
        List<AuditInsertionPoint> fields = withoutHeaders.fieldsOf(request(TOOL_CALL, Map.of()));

        assertThat(fields).extracting(AuditInsertionPoint::name).containsExactly(
                "MCP field: params.name",
                "MCP field: params.arguments.url",
                "MCP field: params.arguments.retries",
                "MCP field: params.arguments.verbose",
                "MCP field: params.arguments.opts.tags[0]",
                "MCP field: params.arguments.none",
                "MCP field: params.arguments.empty",
                "MCP field: params._meta.progressToken");
        assertThat(fields).extracting(AuditInsertionPoint::type).containsOnly(AuditInsertionPointType.PARAM_JSON);
        assertThat(fields).extracting(AuditInsertionPoint::baseValue)
                .containsExactly("fetch", "http://a", "2", "false", "x", "null", "{}", "p1");
    }

    @Test
    void aProbeCallIsFuzzedOnlyAtTheArgumentItAddedAndNeverAtTheHeadersItRepeats() {
        AddedArgumentRegistry addedArguments = new AddedArgumentRegistry();
        addedArguments.record(TOOL_CALL, ArgumentPath.of("url"));
        McpFieldGenerator probes = new McpFieldGenerator(() -> true, new TemplateExpansionRegistry(),
                BurpNativeJsonRpcFields.ABSENT, addedArguments);

        List<AuditInsertionPoint> fields = probes.fieldsOf(request(TOOL_CALL, mcpHeaders()));

        assertThat(fields).extracting(AuditInsertionPoint::name)
                .containsExactly("MCP field: params.arguments.url");
    }

    @Test
    void besideBurpNativeFieldsAProbeCallsAddedScalarIsLeftToBurpSoItIsFuzzedOnce() {
        AddedArgumentRegistry addedArguments = new AddedArgumentRegistry();
        addedArguments.record(TOOL_CALL, ArgumentPath.of("url"));
        McpFieldGenerator probes = new McpFieldGenerator(() -> true, new TemplateExpansionRegistry(),
                BurpNativeJsonRpcFields.PRESENT, addedArguments);

        assertThat(probes.fieldsOf(request(TOOL_CALL, mcpHeaders()))).isEmpty();
    }

    @Test
    void besideBurpNativeFieldsAProbeCallsAddedFieldBurpLeavesUnfuzzedIsStillOffered() {
        AddedArgumentRegistry addedArguments = new AddedArgumentRegistry();
        addedArguments.record(TOOL_CALL, ArgumentPath.of("empty"));
        McpFieldGenerator probes = new McpFieldGenerator(() -> true, new TemplateExpansionRegistry(),
                BurpNativeJsonRpcFields.PRESENT, addedArguments);

        assertThat(probes.fieldsOf(request(TOOL_CALL, mcpHeaders()))).extracting(AuditInsertionPoint::name)
                .containsExactly("MCP field: params.arguments.empty");
    }

    @Test
    void besideBurpNativeFieldsOnlyFieldsBurpLeavesUnfuzzedAreOffered() {
        List<AuditInsertionPoint> fields = besideBurpNativeFields.fieldsOf(request(TOOL_CALL, mcpHeaders()));

        assertThat(fields).extracting(AuditInsertionPoint::name).containsExactly(
                "MCP field: params.name",
                "MCP field: params.arguments.empty",
                "MCP field: params._meta.progressToken",
                "MCP header: Mcp-Method",
                "MCP header: Mcp-Name",
                "MCP header: MCP-Protocol-Version",
                "MCP header: Mcp-Session-Id");
    }

    @Test
    void besideBurpNativeFieldsABodyBurpDoesNotRecogniseKeepsEveryField() {
        String notJsonRpc2 = TOOL_CALL.replace("\"2.0\"", "\"1.0\"");

        assertThat(besideBurpNativeFields.fieldsOf(request(notJsonRpc2, Map.of())))
                .extracting(AuditInsertionPoint::name)
                .containsExactlyElementsOf(names(withoutHeaders.fieldsOf(request(notJsonRpc2, Map.of()))));
    }

    @Test
    void besideBurpNativeFieldsOtherMethodsKeepOnlyMetadataAndEmptyContainers() {
        String complete = "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"completion/complete\",\"params\":"
                + "{\"ref\":{\"type\":\"ref/prompt\",\"name\":\"p\"},\"context\":{},\"_meta\":{\"k\":1}}}";

        assertThat(new McpFieldGenerator(() -> false, new TemplateExpansionRegistry(),
                BurpNativeJsonRpcFields.PRESENT).fieldsOf(request(complete, Map.of())))
                .extracting(AuditInsertionPoint::name)
                .containsExactly("MCP field: params.context", "MCP field: params._meta.k");
    }

    @Test
    void stringPayloadIsInsertedInsideQuotesWithJsonEscaping() {
        AuditInsertionPoint url = field(TOOL_CALL, "MCP field: params.arguments.url");

        String body = bodyOf(url.buildHttpRequestWithPayload(ByteArray.byteArray("a\"b\\c")));

        assertThat(body).contains("\"url\":\"a\\\"b\\\\c\",\"retries\":2");
    }

    @Test
    void numericPayloadGoesInRawWhenItIsANumberAndQuotedOtherwise() {
        AuditInsertionPoint retries = field(TOOL_CALL, "MCP field: params.arguments.retries");

        assertThat(bodyOf(retries.buildHttpRequestWithPayload(ByteArray.byteArray("-7.5"))))
                .contains("\"retries\":-7.5,");
        assertThat(bodyOf(retries.buildHttpRequestWithPayload(ByteArray.byteArray("1 OR 1=1"))))
                .contains("\"retries\":\"1 OR 1=1\",");
    }

    @Test
    void booleanNullAndEmptyContainerPayloadsFollowTheirKind() {
        assertThat(bodyOf(field(TOOL_CALL, "MCP field: params.arguments.verbose")
                .buildHttpRequestWithPayload(ByteArray.byteArray("true")))).contains("\"verbose\":true,");
        assertThat(bodyOf(field(TOOL_CALL, "MCP field: params.arguments.none")
                .buildHttpRequestWithPayload(ByteArray.byteArray("x")))).contains("\"none\":\"x\",");
        assertThat(bodyOf(field(TOOL_CALL, "MCP field: params.arguments.empty")
                .buildHttpRequestWithPayload(ByteArray.byteArray("{\"a\":1}")))).contains("\"empty\":{\"a\":1}}");
    }

    @Test
    void everyPayloadedBodyStaysValidJson() throws Exception {
        for (AuditInsertionPoint point : withoutHeaders.fieldsOf(request(TOOL_CALL, Map.of()))) {
            String body = bodyOf(point.buildHttpRequestWithPayload(ByteArray.byteArray("'\"}]{<x>")));
            assertThat(com.mcpscanner.mcp.McpObjectMapper.INSTANCE.readTree(body).path("params").isObject())
                    .as(point.name()).isTrue();
        }
    }

    @Test
    void splicesAtByteOffsetsAfterMultibyteValues() {
        String body = "{\"method\":\"tools/call\",\"params\":{\"a\":\"日本語\",\"b\":\"z\"}}";
        AuditInsertionPoint b = field(body, "MCP field: params.b");

        assertThat(bodyOf(b.buildHttpRequestWithPayload(ByteArray.byteArray("P"))))
                .isEqualTo("{\"method\":\"tools/call\",\"params\":{\"a\":\"日本語\",\"b\":\"P\"}}");
    }

    @Test
    void highlightCoversTheEncodedPayloadAtItsAbsoluteOffset() {
        HttpRequest request = request(TOOL_CALL, Map.of());
        AuditInsertionPoint url = field(TOOL_CALL, "MCP field: params.arguments.url");
        int valueStart = TOOL_CALL.indexOf("\"http://a\"");

        List<Range> highlights = url.issueHighlights(ByteArray.byteArray("q"));

        assertThat(highlights).singleElement().satisfies(range -> {
            assertThat(range.startIndexInclusive()).isEqualTo(request.bodyOffset() + valueStart);
            assertThat(range.endIndexExclusive()).isEqualTo(request.bodyOffset() + valueStart + 3);
        });
    }

    @Test
    void mcpHeadersBecomeHeaderInsertionPointsWhenSwitchedOn() {
        HttpRequest request = request(TOOL_CALL, mcpHeaders());

        List<AuditInsertionPoint> headerFields = withHeaders.fieldsOf(request).stream()
                .filter(point -> point.type() == AuditInsertionPointType.HEADER).toList();

        assertThat(headerFields).extracting(AuditInsertionPoint::name).containsExactly(
                "MCP header: Mcp-Method", "MCP header: Mcp-Name",
                "MCP header: MCP-Protocol-Version", "MCP header: Mcp-Session-Id");
        assertThat(headerFields).extracting(AuditInsertionPoint::baseValue)
                .containsExactly("tools/call", "fetch", "2024-11-05", "sess-1");
    }

    @Test
    void mcpHeadersAreAbsentWhenSwitchedOff() {
        assertThat(withoutHeaders.fieldsOf(request(TOOL_CALL, mcpHeaders())))
                .extracting(AuditInsertionPoint::type).containsOnly(AuditInsertionPointType.PARAM_JSON);
    }

    @Test
    void headerPayloadReplacesOnlyThatHeaderValue() {
        AuditInsertionPoint sessionId = withHeaders.fieldsOf(request(TOOL_CALL, mcpHeaders())).stream()
                .filter(point -> point.name().equals("MCP header: Mcp-Session-Id")).findFirst().orElseThrow();

        HttpRequest mutated = sessionId.buildHttpRequestWithPayload(ByteArray.byteArray("../x"));

        assertThat(mutated.headerValue("Mcp-Session-Id")).isEqualTo("../x");
        assertThat(mutated.headerValue("Mcp-Method")).isEqualTo("tools/call");
        assertThat(bodyOf(mutated)).isEqualTo(TOOL_CALL);
    }

    @Test
    void headerHighlightPointsAtTheHeaderValue() {
        HttpRequest request = request(TOOL_CALL, mcpHeaders());
        AuditInsertionPoint method = withHeaders.fieldsOf(request).stream()
                .filter(point -> point.name().equals("MCP header: Mcp-Method")).findFirst().orElseThrow();
        String raw = new String(request.toByteArray().getBytes(), StandardCharsets.ISO_8859_1);

        Range range = method.issueHighlights(ByteArray.byteArray("abc")).get(0);

        assertThat(raw.substring(range.startIndexInclusive(), range.startIndexInclusive() + "tools/call".length()))
                .isEqualTo("tools/call");
        assertThat(range.endIndexExclusive() - range.startIndexInclusive()).isEqualTo(3);
    }

    @Test
    void transportAndCredentialHeadersAreNeverOffered() {
        HttpRequest request = request(TOOL_CALL, Map.of("Authorization", "Bearer t", "Cookie", "s=1",
                "Content-Type", "application/json", "Accept", "application/json", "User-Agent", "u"));

        assertThat(withHeaders.fieldsOf(request)).extracting(AuditInsertionPoint::type)
                .containsOnly(AuditInsertionPointType.PARAM_JSON);
    }

    @Test
    void scannerSentinelHeadersAreNeverOffered() {
        HttpRequest request = request(TOOL_CALL, Map.of("X-Mcp-Scanner-Audit-Capability", "signed",
                "X-Mcp-Scanner-Strip-Auth", "1"));

        assertThat(withHeaders.fieldsOf(request)).extracting(AuditInsertionPoint::type)
                .containsOnly(AuditInsertionPointType.PARAM_JSON);
    }

    @Test
    void paramHeadersTheProxyRederivesFromTheBodyAreNeverOffered() {
        HttpRequest request = request(TOOL_CALL, Map.of("Mcp-Param-Tenant", "acme", "mcp-param-priority", "1"));

        assertThat(withHeaders.fieldsOf(request)).extracting(AuditInsertionPoint::type)
                .containsOnly(AuditInsertionPointType.PARAM_JSON);
    }

    @Test
    void callerSuppliedHeadersBecomeHeaderInsertionPointsWhenSwitchedOn() {
        HttpRequest request = request(TOOL_CALL, Map.of("X-Grafana-URL", "http://grafana.local:3000"));

        AuditInsertionPoint upstream = withHeaders.fieldsOf(request).stream()
                .filter(point -> point.type() == AuditInsertionPointType.HEADER).findFirst().orElseThrow();
        HttpRequest mutated = upstream.buildHttpRequestWithPayload(ByteArray.byteArray("http://other.test"));

        assertThat(upstream.name()).isEqualTo("MCP header: X-Grafana-URL");
        assertThat(mutated.headerValue("X-Grafana-URL")).isEqualTo("http://other.test");
        assertThat(withoutHeaders.fieldsOf(request)).extracting(AuditInsertionPoint::type)
                .containsOnly(AuditInsertionPointType.PARAM_JSON);
    }

    @Test
    void parameterlessRequestYieldsOnlyHeaderFields() {
        HttpRequest discover = request("{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"server/discover\"}",
                Map.of("Mcp-Method", "server/discover"));

        assertThat(withHeaders.fieldsOf(discover)).extracting(AuditInsertionPoint::name)
                .containsExactly("MCP header: Mcp-Method");
        assertThat(withoutHeaders.fieldsOf(discover)).isEmpty();
    }



    @Test
    void otherFieldsLeaveMcpNameAlone() {
        AuditInsertionPoint url = withoutHeaders.fieldsOf(request(TOOL_CALL, mcpHeaders())).stream()
                .filter(point -> point.name().equals("MCP field: params.arguments.url")).findFirst().orElseThrow();

        assertThat(url.buildHttpRequestWithPayload(ByteArray.byteArray("x")).headerValue("Mcp-Name")).isEqualTo("fetch");
    }


    private static List<String> names(List<AuditInsertionPoint> fields) {
        return fields.stream().map(AuditInsertionPoint::name).toList();
    }

    private static Map<String, String> mcpHeaders() {
        Map<String, String> headers = new LinkedHashMap<>();
        headers.put("Content-Type", "application/json");
        headers.put("Mcp-Method", "tools/call");
        headers.put("Mcp-Name", "fetch");
        headers.put("MCP-Protocol-Version", "2024-11-05");
        headers.put("Mcp-Session-Id", "sess-1");
        return headers;
    }

    private AuditInsertionPoint field(String body, String name) {
        return withoutHeaders.fieldsOf(request(body, Map.of())).stream()
                .filter(point -> point.name().equals(name)).findFirst().orElseThrow();
    }

    private static HttpRequest request(String body, Map<String, String> headers) {
        return RawHttpRequestStub.post(body, headers);
    }

    private static String bodyOf(HttpRequest request) {
        return new String(request.body().getBytes(), StandardCharsets.UTF_8);
    }
}
