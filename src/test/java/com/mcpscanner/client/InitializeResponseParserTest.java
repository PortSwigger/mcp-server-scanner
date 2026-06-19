package com.mcpscanner.client;

import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Map;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;

class InitializeResponseParserTest {

    private static final String FULL_INITIALIZE_RESPONSE =
            "{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{"
                    + "\"protocolVersion\":\"2024-11-05\","
                    + "\"capabilities\":{\"tools\":{\"listChanged\":true},\"resources\":{}},"
                    + "\"instructions\":\"Use tools/list to discover capabilities.\","
                    + "\"serverInfo\":{\"name\":\"mcp-scanner-test-server\","
                    + "\"version\":\"0.1.0-vuln-fixture\"}}}";

    @Test
    void parsesProtocolVersionFromInitializeResult() {
        String body = "{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{\"protocolVersion\":\"2025-06-18\"}}";

        assertThat(InitializeResponseParser.parseProtocolVersion(body)).contains("2025-06-18");
    }

    @Test
    void returnsEmptyWhenProtocolVersionMissing() {
        String body = "{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{}}";

        assertThat(InitializeResponseParser.parseProtocolVersion(body)).isEqualTo(Optional.empty());
    }

    @Test
    void returnsEmptyOnMalformedJson() {
        assertThat(InitializeResponseParser.parseProtocolVersion("not json")).isEqualTo(Optional.empty());
    }

    @Test
    void parseServerInfoExtractsNameAndVersion() {
        Map<String, String> info = InitializeResponseParser.parseServerInfo(FULL_INITIALIZE_RESPONSE);

        assertThat(info)
                .containsEntry("name", "mcp-scanner-test-server")
                .containsEntry("version", "0.1.0-vuln-fixture");
    }

    @Test
    void parseServerInfoCapturesAdditionalFields() {
        String body = "{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{"
                + "\"serverInfo\":{\"name\":\"foo\",\"version\":\"1\",\"title\":\"Foo MCP\"}}}";

        Map<String, String> info = InitializeResponseParser.parseServerInfo(body);

        assertThat(info)
                .containsEntry("name", "foo")
                .containsEntry("version", "1")
                .containsEntry("title", "Foo MCP");
    }

    @Test
    void parseServerInfoReturnsEmptyWhenMissing() {
        String body = "{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{\"protocolVersion\":\"2024-11-05\"}}";

        assertThat(InitializeResponseParser.parseServerInfo(body)).isEmpty();
    }

    @Test
    void parseServerInfoReturnsEmptyWhenMalformed() {
        assertThat(InitializeResponseParser.parseServerInfo("not json")).isEmpty();
    }

    @Test
    void parseInstructionsReturnsTextValue() {
        assertThat(InitializeResponseParser.parseInstructions(FULL_INITIALIZE_RESPONSE))
                .isEqualTo("Use tools/list to discover capabilities.");
    }

    @Test
    void parseInstructionsReturnsEmptyWhenAbsent() {
        String body = "{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{\"protocolVersion\":\"2024-11-05\"}}";

        assertThat(InitializeResponseParser.parseInstructions(body)).isEmpty();
    }

    @Test
    void parseInstructionsReturnsEmptyForEmptyString() {
        String body = "{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{\"instructions\":\"\"}}";

        assertThat(InitializeResponseParser.parseInstructions(body)).isEmpty();
    }

    @Test
    void parseInstructionsReturnsEmptyWhenNotTextual() {
        String body = "{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{\"instructions\":{\"oops\":true}}}";

        assertThat(InitializeResponseParser.parseInstructions(body)).isEmpty();
    }

    @Test
    void parseInstructionsReturnsEmptyWhenMalformed() {
        assertThat(InitializeResponseParser.parseInstructions("not json")).isEmpty();
    }

    @Test
    void parseCapabilitiesReturnsFullStructure() {
        Map<String, Object> caps = InitializeResponseParser.parseCapabilities(FULL_INITIALIZE_RESPONSE);

        assertThat(caps).containsKey("tools").containsKey("resources");
        @SuppressWarnings("unchecked")
        Map<String, Object> tools = (Map<String, Object>) caps.get("tools");
        assertThat(tools).containsEntry("listChanged", Boolean.TRUE);
    }

    @Test
    void parseCapabilitiesReturnsEmptyWhenAbsent() {
        String body = "{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{\"protocolVersion\":\"2024-11-05\"}}";

        assertThat(InitializeResponseParser.parseCapabilities(body)).isEmpty();
    }

    @Test
    void parseCapabilitiesReturnsEmptyForEmptyObject() {
        String body = "{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{\"capabilities\":{}}}";

        assertThat(InitializeResponseParser.parseCapabilities(body)).isEmpty();
    }

    @Test
    void parseCapabilitiesReturnsEmptyWhenMalformed() {
        assertThat(InitializeResponseParser.parseCapabilities("not json")).isEmpty();
    }

    @Test
    void parseCapabilitiesPreservesNestedObjectsArraysAndBooleans() {
        String body = "{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{\"capabilities\":{"
                + "\"experimental\":{\"flags\":[\"a\",\"b\"],\"enabled\":true},"
                + "\"depth\":3"
                + "}}}";

        Map<String, Object> caps = InitializeResponseParser.parseCapabilities(body);

        @SuppressWarnings("unchecked")
        Map<String, Object> experimental = (Map<String, Object>) caps.get("experimental");
        assertThat(experimental).containsEntry("enabled", Boolean.TRUE);
        assertThat(experimental.get("flags")).isInstanceOf(List.class);
        @SuppressWarnings("unchecked")
        List<Object> flags = (List<Object>) experimental.get("flags");
        assertThat(flags).containsExactly("a", "b");
        assertThat(caps.get("depth")).isInstanceOf(Number.class);
    }
}
