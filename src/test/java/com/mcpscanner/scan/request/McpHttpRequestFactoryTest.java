package com.mcpscanner.scan.request;

import com.mcpscanner.mcp.FramedOperation;
import com.mcpscanner.mcp.ScannerSentinels;
import com.mcpscanner.testutil.PlainFraming;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.mcpscanner.mcp.McpObjectMapper;
import com.mcpscanner.mcp.McpOperationFraming;
import com.mcpscanner.mcp.McpToolDefinition;
import com.mcpscanner.mcp.ParamHeaderFramer;
import com.mcpscanner.mcp.ParamHeaderValue;
import com.mcpscanner.mcp.ToolParamHeaders;
import com.mcpscanner.core.protocol.McpRequests;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import java.nio.charset.StandardCharsets;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicLong;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class McpHttpRequestFactoryTest {

    private static final String ENDPOINT = "http://127.0.0.1:8000/mcp";
    private static final Map<String, String> ROUTING_SESSION = Map.of("mcp-protocol-version", "2026-07-28");

    private final AtomicLong ids = new AtomicLong(40);
    private static final String PROTOCOL_VERSION_META = "io.modelcontextprotocol/protocolVersion";
    private static final McpOperationFraming.Framer MODERN_FRAMER = PlainFraming.withOperations(
            (method, params, id) -> method.equals("tools/call")
                    ? McpRequests.modernOperation(method, "burp", "1", params, id)
                    : McpRequests.modern(method, "burp", "1", params, id));

    private final McpHttpRequestFactory factory = new McpHttpRequestFactory(ids::incrementAndGet, PlainFraming.framer());

    @Test
    void requestCarriesEnvelopeWithAllocatedId() throws Exception {
        JsonNode body = body(factory.raw(ENDPOINT, ProtocolMessages.ping(), Map.of()));

        assertThat(body.path("jsonrpc").asText()).isEqualTo("2.0");
        assertThat(body.path("id").asLong()).isEqualTo(41);
        assertThat(body.path("method").asText()).isEqualTo("ping");
        assertThat(body.path("params").has("_meta")).isTrue();
    }

    @Test
    void notificationHasNoId() throws Exception {
        JsonNode body = body(factory.raw(ENDPOINT, ProtocolMessages.initializedNotification(), Map.of()));

        assertThat(body.has("id")).isFalse();
        assertThat(body.path("params").isObject()).isTrue();
    }

    @Test
    void parameterlessRequestCarriesNoParameters() throws Exception {
        assertThat(body(factory.raw(ENDPOINT, ProtocolMessages.serverDiscover(), Map.of())).path("params")).isEmpty();
    }

    @Test
    void carriesSessionHeadersVerbatimExceptTheSessionManagedAuthorization() {
        Map<String, String> session = new LinkedHashMap<>();
        session.put("Mcp-Session-Id", "sess-9");
        session.put("MCP-Protocol-Version", "2025-06-18");
        session.put("X-Api-Key", "k");
        session.put("authorization", "Bearer stale");

        String raw = factory.raw(ENDPOINT, ProtocolMessages.ping(), session);

        assertThat(raw).contains("\r\nMcp-Session-Id: sess-9\r\n", "\r\nMCP-Protocol-Version: 2025-06-18\r\n",
                "\r\nX-Api-Key: k\r\n").doesNotContainIgnoringCase("authorization");
    }

    @Test
    void aScannerLaunchedRequestRecordsWhatItFramedSoTheProxyCanTellAFuzzedOperationHeader() {
        String raw = factory.raw(ENDPOINT, ProtocolMessages.ping(), Map.of("MCP-Protocol-Version", "2025-06-18"));

        assertThat(raw).contains("\r\n" + ScannerSentinels.FRAMED_OPERATION_HEADER + ": "
                + FramedOperation.encode(Map.of("MCP-Protocol-Version", "2025-06-18")) + "\r\n");
    }

    @Test
    void takesRoutingHeadersAndTheStatelessEnvelopeFromTheSharedFramerAndKeepsTheProgressToken() throws Exception {
        McpHttpRequestFactory modern = new McpHttpRequestFactory(ids::incrementAndGet, MODERN_FRAMER);
        McpMessage call = (McpMessage) RequestGenerator.standard().scanAll(SampleSurfaces.full(),
                family -> family == RequestFamily.TOOLS_CALL).messages().get(0);

        String raw = modern.raw(ENDPOINT, call, ROUTING_SESSION);

        assertThat(raw).contains("\r\nMcp-Method: tools/call\r\n", "\r\nMcp-Name: lookup\r\n");
        assertThat(body(raw).path("params").path("_meta").path(PROTOCOL_VERSION_META).asText()).isEqualTo("2026-07-28");
        assertThat(body(raw).path("params").path("_meta").path("progressToken").asText()).isNotEmpty();
        assertThat(body(modern.raw(ENDPOINT, ProtocolMessages.cancelledNotification(), ROUTING_SESSION))
                .path("params").has("_meta")).isFalse();
    }

    @ParameterizedTest
    @ValueSource(strings = {"2024-11-05", "2025-03-26", "2025-06-18", "2025-11-25"})
    void sendsNoEnvelopeOnHandshakeVersions(String version) throws Exception {
        JsonNode ping = body(factory.raw(ENDPOINT, ProtocolMessages.ping(), Map.of("MCP-Protocol-Version", version)));

        assertThat(ping.path("params").path("_meta").has(PROTOCOL_VERSION_META)).isFalse();
    }

    @ParameterizedTest
    @ValueSource(strings = {"2024-11-05", "2025-06-18", "2025-11-25"})
    void omitsRoutingHeadersForProtocolVersionsThatDoNotDefineThem(String version) {
        McpMessage call = (McpMessage) RequestGenerator.standard().scanAll(SampleSurfaces.full(),
                family -> family == RequestFamily.TOOLS_CALL).messages().get(0);

        assertThat(factory.raw(ENDPOINT, call, Map.of("MCP-Protocol-Version", version)))
                .doesNotContain("Mcp-Method", "Mcp-Name");
        assertThat(factory.raw(ENDPOINT, call, Map.of())).doesNotContain("Mcp-Method", "Mcp-Name");
    }


    @Test
    void sendsTheParamHeadersAToolDeclaresFromTheArgumentsInTheBody() throws Exception {
        String raw = paramHeaderFactory(MODERN_FRAMER).raw(ENDPOINT, tenantCall(" fuzzedé"), ROUTING_SESSION);

        assertThat(body(raw).path("params").path("arguments").path("tenant").asText()).isEqualTo(" fuzzedé");
        assertThat(raw).contains("\r\nMcp-Param-Tenant: " + ParamHeaderValue.encoded(" fuzzedé") + "\r\n",
                "\r\nMcp-Param-Priority: 7\r\n");
    }

    @Test
    void sendsNoParamHeadersOnHandshakeVersions() {
        String raw = paramHeaderFactory(PlainFraming.framer()).raw(ENDPOINT, tenantCall("acme"),
                Map.of("MCP-Protocol-Version", "2025-06-18"));

        assertThat(raw).doesNotContain("Mcp-Param-");
    }

    @Test
    void sendsNoParamHeadersOutsideToolCalls() {
        McpMessage prompt = McpMessage.namedRequest(RequestFamily.PROMPTS_GET, "prompts/get",
                McpParams.empty().put("name", "lookup").set("arguments", McpParams.empty().put("tenant", "acme")),
                "lookup");

        McpOperationFraming.Framer modernOperations = PlainFraming.withOperations(
                (method, params, id) -> McpRequests.modernOperation(method, "burp", "1", params, id));

        assertThat(paramHeaderFactory(modernOperations).raw(ENDPOINT, prompt, ROUTING_SESSION))
                .contains("\r\nMcp-Method: prompts/get\r\n").doesNotContain("Mcp-Param-");
    }

    private McpHttpRequestFactory paramHeaderFactory(McpOperationFraming.Framer framer) {
        ToolParamHeaders tools = new ToolParamHeaders(warning -> {});
        tools.learn(List.of(new McpToolDefinition("lookup", "", "{\"type\":\"object\",\"properties\":{"
                + "\"tenant\":{\"type\":\"string\",\"x-mcp-header\":\"Tenant\"},"
                + "\"priority\":{\"type\":\"integer\",\"x-mcp-header\":\"Priority\"}}}")));
        return new McpHttpRequestFactory(ids::incrementAndGet, new ParamHeaderFramer(framer, tools));
    }

    private static McpMessage tenantCall(String tenant) {
        ObjectNode arguments = McpParams.empty().put("tenant", tenant).put("priority", 7);
        return McpMessage.namedRequest(RequestFamily.TOOLS_CALL, "tools/call",
                McpParams.empty().put("name", "lookup").set("arguments", arguments), "lookup");
    }

    @Test
    void requestLineHostAndContentHeaders() {
        String raw = factory.raw("https://h.example/a/mcp?k=v", ProtocolMessages.ping(), Map.of());

        assertThat(raw).startsWith("POST /a/mcp?k=v HTTP/1.1\r\nHost: h.example\r\n")
                .contains("\r\nContent-Type: application/json\r\n",
                        "\r\nAccept: application/json, text/event-stream\r\n");
        assertThat(factory.raw("http://h:8080", ProtocolMessages.ping(), Map.of()))
                .startsWith("POST / HTTP/1.1\r\nHost: h:8080\r\n");
    }

    @Test
    void asksBurpToCloseTheConnectionWhateverTheSessionHeadersSay() {
        String raw = factory.raw(ENDPOINT, ProtocolMessages.ping(), Map.of("connection", "keep-alive"));

        assertThat(raw).contains("\r\nConnection: close\r\n").doesNotContain("keep-alive");
    }

    @Test
    void contentLengthCountsUtf8Bytes() {
        McpMessage message = McpMessage.request(RequestFamily.PING, "ping", McpParams.empty().put("x", "日本☃"));
        String raw = factory.raw(ENDPOINT, message, Map.of());
        String body = raw.substring(raw.indexOf("\r\n\r\n") + 4);

        assertThat(raw).contains("Content-Length: " + body.getBytes(StandardCharsets.UTF_8).length + "\r\n");
    }

    @ParameterizedTest
    @ValueSource(strings = {"a\rb", "a\nb", "a\0b"})
    void rejectsHeaderValuesWithControlCharacters(String value) {
        assertThatThrownBy(() -> factory.raw(ENDPOINT, ProtocolMessages.ping(), Map.of("X-Test", value)))
                .isInstanceOf(IllegalArgumentException.class);
    }

    @ParameterizedTest
    @ValueSource(strings = {"Bad Name", "X\r\nY", ""})
    void rejectsInvalidHeaderNames(String name) {
        assertThatThrownBy(() -> factory.raw(ENDPOINT, ProtocolMessages.ping(), Map.of(name, "v")))
                .isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void buildingTwiceDoesNotMutateTheMessage() {
        McpMessage message = ProtocolMessages.initialize();
        factory.raw(ENDPOINT, message, Map.of());

        assertThat(message.params().orElseThrow().has("id")).isFalse();
    }

    private static JsonNode body(String raw) throws Exception {
        return McpObjectMapper.INSTANCE.readTree(raw.substring(raw.indexOf("\r\n\r\n") + 4));
    }
}
