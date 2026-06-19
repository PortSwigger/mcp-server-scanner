package com.mcpscanner.client;

import com.fasterxml.jackson.databind.JsonNode;
import com.mcpscanner.mcp.IconDescriptor;
import com.mcpscanner.mcp.McpObjectMapper;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

class IconParserTest {

    private static JsonNode envelope(String json) throws Exception {
        return McpObjectMapper.INSTANCE.readTree(json);
    }

    @Test
    void parseIcons_extractsIconsFromToolsArray() throws Exception {
        JsonNode envelope = envelope("{\"jsonrpc\":\"2.0\",\"id\":0,\"result\":{\"tools\":["
                + "{\"name\":\"logo_tool\",\"icons\":["
                + "{\"src\":\"https://cdn.example/logo.png\",\"mimeType\":\"image/png\","
                + "\"sizes\":[\"128x128\"]}]}]}}");

        Map<String, List<IconDescriptor>> icons = IconParser.parseIcons(envelope, "tools");

        assertThat(icons).containsOnlyKeys("logo_tool");
        assertThat(icons.get("logo_tool")).hasSize(1);
        IconDescriptor icon = icons.get("logo_tool").get(0);
        assertThat(icon.src()).isEqualTo("https://cdn.example/logo.png");
        assertThat(icon.mimeType()).isEqualTo("image/png");
        assertThat(icon.sizes()).containsExactly("128x128");
    }

    @Test
    void parseIcons_extractsIconsFromResourcesArray() throws Exception {
        JsonNode envelope = envelope("{\"result\":{\"resources\":["
                + "{\"name\":\"readme\",\"icons\":["
                + "{\"src\":\"file:///etc/passwd\",\"mimeType\":\"image/png\"}]}]}}");

        Map<String, List<IconDescriptor>> icons = IconParser.parseIcons(envelope, "resources");

        assertThat(icons.get("readme").get(0).src()).isEqualTo("file:///etc/passwd");
    }

    @Test
    void parseIcons_extractsIconsFromPromptsArray() throws Exception {
        JsonNode envelope = envelope("{\"result\":{\"prompts\":["
                + "{\"name\":\"summarise\",\"icons\":["
                + "{\"src\":\"https://server.test/p.svg\",\"mimeType\":\"image/svg+xml\"}]}]}}");

        Map<String, List<IconDescriptor>> icons = IconParser.parseIcons(envelope, "prompts");

        assertThat(icons.get("summarise").get(0).mimeType()).isEqualTo("image/svg+xml");
    }

    @Test
    void parseIcons_returnsEmptyMapWhenNoIcons() throws Exception {
        JsonNode envelope = envelope("{\"result\":{\"tools\":[{\"name\":\"plain\"}]}}");

        assertThat(IconParser.parseIcons(envelope, "tools")).isEmpty();
    }

    @Test
    void parseIcons_returnsEmptyMapForMissingArray() throws Exception {
        assertThat(IconParser.parseIcons(envelope("{\"result\":{}}"), "tools")).isEmpty();
    }

    @Test
    void parseIcons_returnsEmptyMapForNullEnvelope() {
        assertThat(IconParser.parseIcons(null, "tools")).isEmpty();
    }

    @Test
    void parseIcons_skipsEntriesWithoutName() throws Exception {
        JsonNode envelope = envelope("{\"result\":{\"tools\":["
                + "{\"icons\":[{\"src\":\"https://e.test/x.png\"}]},"
                + "{\"name\":\"good\",\"icons\":[{\"src\":\"https://e.test/y.png\"}]}]}}");

        Map<String, List<IconDescriptor>> icons = IconParser.parseIcons(envelope, "tools");

        assertThat(icons).containsOnlyKeys("good");
    }

    @Test
    void parseServerIcons_extractsHaMcpCrossOriginSvgIcon() throws Exception {
        // homeassistant-ai/ha-mcp v7.6.0 initialize envelope (SEP-973 server-level icon).
        JsonNode envelope = envelope("{\"jsonrpc\":\"2.0\",\"id\":0,\"result\":{\"serverInfo\":{"
                + "\"name\":\"ha-mcp\",\"version\":\"7.6.0\",\"icons\":["
                + "{\"src\":\"https://raw.githubusercontent.com/home-assistant/brands/master/"
                + "core_integrations/mcp/icon.svg\",\"mimeType\":\"image/svg+xml\"}]}}}");

        List<IconDescriptor> icons = IconParser.parseServerIcons(envelope);

        assertThat(icons).hasSize(1);
        assertThat(icons.get(0).src()).contains("raw.githubusercontent.com").endsWith("icon.svg");
        assertThat(icons.get(0).mimeType()).isEqualTo("image/svg+xml");
    }

    @Test
    void parseServerIcons_extractsCourtListenerDataIcons() throws Exception {
        // freelawproject/courtlistener-api-client: data:svg + data:png server-level icons.
        JsonNode envelope = envelope("{\"result\":{\"serverInfo\":{\"name\":\"courtlistener\",\"icons\":["
                + "{\"src\":\"data:image/svg+xml;base64,PHN2Zz48L3N2Zz4=\",\"mimeType\":\"image/svg+xml\"},"
                + "{\"src\":\"data:image/png;base64,iVBORw0KGgo=\",\"mimeType\":\"image/png\"}]}}}");

        List<IconDescriptor> icons = IconParser.parseServerIcons(envelope);

        assertThat(icons).hasSize(2);
        assertThat(icons.get(0).src()).startsWith("data:image/svg+xml");
        assertThat(icons.get(1).src()).startsWith("data:image/png");
    }

    @Test
    void parseServerIcons_returnsEmptyWhenAbsent() throws Exception {
        assertThat(IconParser.parseServerIcons(envelope(
                "{\"result\":{\"serverInfo\":{\"name\":\"plain\"}}}"))).isEmpty();
    }

    @Test
    void parseServerIcons_returnsEmptyForNullEnvelope() {
        assertThat(IconParser.parseServerIcons(null)).isEmpty();
    }

    @Test
    void parseIcons_supportsMultipleIconsPerObject() throws Exception {
        JsonNode envelope = envelope("{\"result\":{\"tools\":["
                + "{\"name\":\"multi\",\"icons\":["
                + "{\"src\":\"https://e.test/a.png\"},"
                + "{\"src\":\"https://e.test/b.png\"}]}]}}");

        Map<String, List<IconDescriptor>> icons = IconParser.parseIcons(envelope, "tools");

        assertThat(icons.get("multi")).hasSize(2);
    }
}
