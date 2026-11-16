package com.mcpscanner.ui.access;

import com.mcpscanner.access.mining.WriteToolOptIn;
import com.mcpscanner.mcp.McpToolDefinition;
import com.mcpscanner.scan.ScanInventory;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Optional;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;

class MiningConsentTest {

    private final MiningUiFixture fixture = new MiningUiFixture();
    private final MiningConsent consent = new MiningConsent(fixture.mining, fixture.dialogs);

    @AfterEach
    void tearDown() {
        fixture.close();
    }

    @Test
    void namesTheToolsMiningWillCallIncludingOptedInWriteTools() {
        fixture.inventory.set(Optional.of(ScanInventory.toolsOnly(List.of(MiningUiFixture.LIST_DOCUMENTS,
                new McpToolDefinition("get_profile", "", "{\"type\":\"object\"}"),
                MiningUiFixture.ARCHIVE_DOCUMENT))));

        assertThat(consent.toolsToCall().names()).containsExactly("list_documents", "get_profile");
        assertThat(consent.toolsToCall().mayWrite()).containsExactly("get_profile");

        optInArchive();
        assertThat(consent.toolsToCall().names()).containsExactly("list_documents", "get_profile", "archive_document");
        assertThat(consent.toolsToCall().mayWrite()).containsExactly("get_profile", "archive_document");
    }

    @Test
    void collectingOnlyReadOnlyToolsStartsWithoutAsking() {
        assertThat(consent.confirmMining(null)).isTrue();

        assertThat(fixture.dialogs.asked).isEmpty();
    }

    @Test
    void anOptedInWriteToolForcesTheConfirmation() {
        optInArchive();
        fixture.dialogs.confirmAnswers.add(false);

        assertThat(consent.confirmMining(null)).isFalse();

        assertThat(fixture.dialogs.asked).containsExactly("confirm-mining");
        assertThat(fixture.dialogs.confirmedTools).extracting(ToolsToCall::mayWrite)
                .containsExactly(List.of("archive_document"));
    }

    @Test
    void anUnannotatedToolCountsAsMayWrite() {
        fixture.inventory.set(Optional.of(ScanInventory.toolsOnly(List.of(
                new McpToolDefinition("get_profile", "", "{\"type\":\"object\"}")))));

        consent.confirmMining(null);

        assertThat(fixture.dialogs.asked).containsExactly("confirm-mining");
    }

    @Test
    void asksOncePerConnection() {
        optInArchive();
        assertThat(consent.confirmMining(null)).isTrue();
        assertThat(consent.confirmMining(null)).isTrue();
        assertThat(fixture.dialogs.asked).containsExactly("confirm-mining");

        fixture.mining.reset();
        assertThat(consent.confirmMining(null)).isTrue();
        assertThat(fixture.dialogs.asked).containsExactly("confirm-mining", "confirm-mining");
    }

    @Test
    void readOnlyCollectingIsNotConsentForALaterWriteTool() {
        consent.confirmMining(null);
        optInArchive();

        consent.confirmMining(null);

        assertThat(fixture.dialogs.asked).containsExactly("confirm-mining");
    }

    @Test
    void aRefusalIsNotRemembered() {
        optInArchive();
        fixture.dialogs.confirmAnswers.add(false);

        assertThat(consent.confirmMining(null)).isFalse();
        assertThat(consent.confirmMining(null)).isTrue();
        assertThat(fixture.dialogs.asked).containsExactly("confirm-mining", "confirm-mining");
    }

    @Test
    void theMineFirstPromptListsTheSameToolsAndMineCountsAsConsent() {
        optInArchive();
        fixture.dialogs.mineFirstAnswers.add(MineFirstChoice.MINE);

        assertThat(consent.mineFirst(null)).isEqualTo(MineFirstChoice.MINE);
        assertThat(consent.confirmMining(null)).isTrue();

        assertThat(fixture.dialogs.mineFirstTools).extracting(ToolsToCall::names)
                .containsExactly(List.of("list_documents", "get_document", "archive_document"));
        assertThat(fixture.dialogs.asked).containsExactly("mine-first");
    }

    @Test
    void continuingWithoutMiningIsNotConsent() {
        optInArchive();
        fixture.dialogs.mineFirstAnswers.add(MineFirstChoice.CONTINUE_WITHOUT);

        consent.mineFirst(null);
        consent.confirmMining(null);

        assertThat(fixture.dialogs.asked).containsExactly("mine-first", "confirm-mining");
    }

    private void optInArchive() {
        fixture.mining.preferences().setWriteTools(WriteToolOptIn.selected(Set.of("archive_document")));
    }
}
