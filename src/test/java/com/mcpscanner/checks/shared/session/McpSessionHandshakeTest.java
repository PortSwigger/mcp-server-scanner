package com.mcpscanner.checks.shared.session;

import burp.api.montoya.http.message.requests.HttpRequest;
import com.fasterxml.jackson.databind.JsonNode;
import com.mcpscanner.mcp.McpObjectMapper;
import com.mcpscanner.core.protocol.McpRequests;
import com.mcpscanner.testutil.ImmutableHttpRequest;
import org.junit.jupiter.api.Test;

import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

class McpSessionHandshakeTest {

    private static final String INITIALIZE_ID = "anonymous-probe-initialize";

    private final McpSessionHandshake handshake = McpSessionHandshake.named(INITIALIZE_ID);

    private static HttpRequest probe(Map<String, String> headers) {
        return ImmutableHttpRequest.post("http://mcp.example/MCP?x=1", headers, "{\"jsonrpc\":\"2.0\",\"id\":11,\"method\":\"tools/call\",\"params\":{\"name\":\"read_secret\",\"arguments\":{}}}");
    }

    private static JsonNode body(HttpRequest request) throws Exception {
        return McpObjectMapper.INSTANCE.readTree(request.bodyToString());
    }

    @Test
    void initializeKeepsTheProbePathAndHeadersButNeverASession() throws Exception {
        HttpRequest initialize = handshake.initialize(probe(Map.of("X-Forwarded-For", "127.0.0.1",
                "Mcp-Session-Id", "stale")));

        assertThat(initialize.path()).isEqualTo("/MCP?x=1");
        assertThat(initialize.headerValue("X-Forwarded-For")).isEqualTo("127.0.0.1");
        assertThat(initialize.headerValue("Mcp-Session-Id")).isNull();
        JsonNode message = body(initialize);
        assertThat(message.path("method").asText()).isEqualTo("initialize");
        assertThat(message.path("id").asText()).isEqualTo(INITIALIZE_ID);
        assertThat(message.path("params").path("clientInfo").path("name").asText()).isNotBlank();
    }

    @Test
    void initializeUsesTheDeclaredHandshakeVersionOrTheLatestHandshakeVersion() throws Exception {
        assertThat(body(handshake.initialize(probe(Map.of("MCP-Protocol-Version", "2025-06-18"))))
                .path("params").path("protocolVersion").asText()).isEqualTo("2025-06-18");
        assertThat(body(handshake.initialize(probe(Map.of()))).path("params").path("protocolVersion").asText())
                .isEqualTo(McpRequests.supportedInitializeVersions().get(0));
        assertThat(body(handshake.initialize(probe(Map.of("MCP-Protocol-Version", McpRequests.MODERN_VERSION))))
                .path("params").path("protocolVersion").asText()).isEqualTo(McpRequests.supportedInitializeVersions().get(0));
    }

    @Test
    void anAbsentHeaderUsesTheConfiguredVersion() throws Exception {
        assertThat(body(McpSessionHandshake.defaultingTo(INITIALIZE_ID, "2025-03-26").initialize(probe(Map.of())))
                .path("params").path("protocolVersion").asText()).isEqualTo("2025-03-26");
    }

    @Test
    void initializedIsANotificationInTheIssuedSession() throws Exception {
        HttpRequest initialized = handshake.initialized(probe(Map.of()), "fresh");

        assertThat(initialized.headerValue("Mcp-Session-Id")).isEqualTo("fresh");
        assertThat(body(initialized).path("method").asText()).isEqualTo("notifications/initialized");
        assertThat(body(initialized).has("id")).isFalse();
    }

    @Test
    void sendsTheSameInitializeAndInitializedMessagesWhateverTheKeyOrder() throws Exception {
        assertThat(body(handshake.initialize(probe(Map.of("MCP-Protocol-Version", "2025-06-18")))))
                .isEqualTo(McpObjectMapper.INSTANCE.readTree("{\"jsonrpc\":\"2.0\",\"method\":\"initialize\","
                        + "\"id\":\"anonymous-probe-initialize\",\"params\":{"
                        + "\"protocolVersion\":\"2025-06-18\",\"capabilities\":{},"
                        + "\"clientInfo\":{\"name\":\"mcp-server-scanner\",\"version\":\"2.1.2\"}}}"));
        assertThat(handshake.initialized(probe(Map.of()), "fresh").bodyToString())
                .isEqualTo("{\"jsonrpc\":\"2.0\",\"method\":\"notifications/initialized\"}");
    }
}
