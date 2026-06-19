package com.mcpscanner.ui;

import com.mcpscanner.mcp.ServerMetadata;
import org.junit.jupiter.api.Test;

import java.util.LinkedHashMap;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

class ServerInfoPanelTest {

    private final ServerInfoPanel panel = new ServerInfoPanel();

    @Test
    void initialStateRendersEmptyPlaceholders() {
        assertThat(panel.serverInfoAreaForTest().getText())
                .contains("did not advertise serverInfo");
        assertThat(panel.instructionsAreaForTest().getText())
                .contains("did not return instructions");
        assertThat(panel.capabilitiesAreaForTest().getText())
                .contains("did not advertise capabilities");
    }

    @Test
    void populateRendersServerInfoFields() {
        Map<String, String> info = new LinkedHashMap<>();
        info.put("name", "test-server");
        info.put("version", "1.2.3");

        panel.populate(new ServerMetadata(info, "", Map.of()));

        assertThat(panel.serverInfoAreaForTest().getText())
                .contains("name: test-server")
                .contains("version: 1.2.3");
    }

    @Test
    void populateRendersInstructionsText() {
        panel.populate(new ServerMetadata(Map.of(), "use tools/list to start", Map.of()));

        assertThat(panel.instructionsAreaForTest().getText())
                .isEqualTo("use tools/list to start");
    }

    @Test
    void populateRendersCapabilitiesAsJson() {
        Map<String, Object> capabilities = new LinkedHashMap<>();
        capabilities.put("tools", Map.of("listChanged", true));

        panel.populate(new ServerMetadata(Map.of(), "", capabilities));

        assertThat(panel.capabilitiesAreaForTest().getText())
                .contains("tools")
                .contains("listChanged");
    }

    @Test
    void populateWithEmptyMetadataResetsToPlaceholders() {
        panel.populate(new ServerMetadata(
                Map.of("name", "x"), "instructions", Map.of("tools", Map.of())));
        panel.populate(ServerMetadata.empty());

        assertThat(panel.serverInfoAreaForTest().getText())
                .contains("did not advertise serverInfo");
        assertThat(panel.instructionsAreaForTest().getText())
                .contains("did not return instructions");
        assertThat(panel.capabilitiesAreaForTest().getText())
                .contains("did not advertise capabilities");
    }
}
