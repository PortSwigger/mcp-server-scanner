package com.mcpscanner.access.mining;

import com.mcpscanner.testutil.InMemoryPreferences;
import burp.api.montoya.logging.Logging;
import burp.api.montoya.persistence.PersistedObject;
import com.mcpscanner.config.ExtensionConfigStore;
import com.mcpscanner.identity.Identity;
import com.mcpscanner.identity.IdentityStore;
import com.mcpscanner.identity.MinedSource;
import com.mcpscanner.identity.MinedValue;
import com.mcpscanner.identity.ValueScope;
import com.mcpscanner.logging.McpEventLog;
import com.mcpscanner.testutil.InMemoryPersistedObject;
import org.junit.jupiter.api.Test;

import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;

class SavedMiningProjectCompatibilityTest {

    private static final String SAVED_IDENTITIES = "[{\"id\":\"b\",\"name\":\"bob\",\"role\":\"PEER\","
            + "\"authKind\":\"BEARER\",\"compared\":true,\"ownedObjects\":[{\"argument\":\"doc_id\","
            + "\"value\":\"d-bob-0042\",\"provenance\":\"MINED\",\"source\":{\"operation\":\"tools/call list_documents\","
            + "\"fieldPath\":\"documents[0].doc_id\"},\"scope\":\"PRIVATE\"}]}]";

    private final PersistedObject saved = InMemoryPersistedObject.create();

    @Test
    void aProjectSavedBeforeTheCollectIdsRenameStillLoadsItsCollectedIdsAndSettings() {
        saved.setString("mcp.identities", SAVED_IDENTITIES);
        saved.setString("mcp.mining.passes", "4");
        saved.setString("mcp.mining.write_tools", "{\"mode\":\"SELECTED\",\"selected\":[\"archive_document\"]}");
        saved.setBoolean("mcp.mining.mined_in_write_tools", true);
        ExtensionConfigStore config = new ExtensionConfigStore(saved, new InMemoryPreferences(), mock(Logging.class));

        MiningPreferences preferences = new MiningPreferences(config);
        assertThat(preferences.passes()).isEqualTo(4);
        assertThat(preferences.writeTools()).isEqualTo(WriteToolOptIn.selected(Set.of("archive_document")));
        assertThat(preferences.minedIdsInWriteTools()).isTrue();
        assertThat(new IdentityStore(config, McpEventLog.noop()).load().identities()).singleElement()
                .extracting(Identity::ownedValues).satisfies(values -> assertThat(values.mined()).containsExactly(
                        new MinedValue("doc_id", "d-bob-0042",
                                new MinedSource("tools/call list_documents", "documents[0].doc_id"),
                                ValueScope.PRIVATE)));
    }
}
