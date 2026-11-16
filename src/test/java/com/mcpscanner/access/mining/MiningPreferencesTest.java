package com.mcpscanner.access.mining;

import com.mcpscanner.config.ExtensionConfigStore;
import com.mcpscanner.mcp.McpToolDefinition;
import com.mcpscanner.testutil.InMemoryPersistedObject;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Set;

import static com.mcpscanner.access.mining.ScriptedServer.noArguments;
import static com.mcpscanner.access.mining.ScriptedServer.readOnlyTool;
import static com.mcpscanner.access.mining.ScriptedServer.unannotatedTool;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class MiningPreferencesTest {

    private static final McpToolDefinition LIST = readOnlyTool("notes_list", noArguments());
    private static final McpToolDefinition EXPORT = unannotatedTool("notes_export", noArguments());
    private static final McpToolDefinition DELETE = readOnlyTool("notes_delete", noArguments());

    private final ExtensionConfigStore config = InMemoryPersistedObject.configStore();
    private final MiningPreferences preferences = new MiningPreferences(config);

    @Test
    void defaultsToTwoPassesAndReadOnlyTools() {
        assertThat(preferences.passes()).isEqualTo(MiningSettings.DEFAULT_PASSES);
        assertThat(preferences.writeTools()).isEqualTo(WriteToolOptIn.NONE);
        assertThat(preferences.settings(List.of(LIST, EXPORT)).allowedTools()).isEmpty();
    }

    @Test
    void theRequestCeilingComesFromTheCollectIdsRequestsPerUserSetting() {
        assertThat(preferences.settings(List.of(LIST)).requestCeiling()).isEqualTo(MiningSettings.NO_REQUEST_CEILING);

        config.setResourceCap(com.mcpscanner.config.ResourceCap.MINING_REQUESTS_PER_USER, 750L);

        assertThat(preferences.settings(List.of(LIST)).requestCeiling()).isEqualTo(750);
    }

    @Test
    void minedIdsStayOutOfWriteToolsUntilTurnedOnAndTheChoiceIsPersisted() {
        assertThat(preferences.minedIdsInWriteTools()).isFalse();

        preferences.setMinedIdsInWriteTools(true);

        assertThat(new MiningPreferences(config).minedIdsInWriteTools()).isTrue();
    }

    @Test
    void persistsPassesAcrossInstances() {
        preferences.setPasses(4);

        assertThat(new MiningPreferences(config).passes()).isEqualTo(4);
        assertThat(new MiningPreferences(config).settings(List.of()).passes()).isEqualTo(4);
    }

    @Test
    void rejectsPassesOutsideOneToFive() {
        assertThatThrownBy(() -> preferences.setPasses(0)).isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> preferences.setPasses(6)).isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void anUnreadableStoredPassCountFallsBackToTheDefault() {
        config.setMiningPasses("nine");

        assertThat(preferences.passes()).isEqualTo(MiningSettings.DEFAULT_PASSES);
    }

    @Test
    void allToolsAllowsEveryWriteToolButNoReadOnlyOne() {
        preferences.setWriteTools(WriteToolOptIn.ALL);

        assertThat(new MiningPreferences(config).settings(List.of(LIST, EXPORT, DELETE)).allowedTools())
                .containsExactlyInAnyOrder("notes_export", "notes_delete");
    }

    @Test
    void selectedToolsAllowsOnlyThePickedOnesAndPersistsThem() {
        preferences.setWriteTools(WriteToolOptIn.selected(Set.of("notes_export", "a,b\nc")));

        WriteToolOptIn restored = new MiningPreferences(config).writeTools();
        assertThat(restored.mode()).isEqualTo(WriteToolOptIn.Mode.SELECTED);
        assertThat(restored.selected()).containsExactlyInAnyOrder("notes_export", "a,b\nc");
        assertThat(new MiningPreferences(config).settings(List.of(LIST, EXPORT, DELETE)).allowedTools())
                .containsExactly("notes_export");
    }

    @Test
    void listsTheToolsThatCountAsWrites() {
        assertThat(MiningPreferences.writeToolsIn(List.of(LIST, EXPORT, DELETE)))
                .extracting(McpToolDefinition::name).containsExactly("notes_export", "notes_delete");
    }
}
