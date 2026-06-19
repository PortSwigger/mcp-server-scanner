package com.mcpscanner.ui;

import com.mcpscanner.mcp.McpPromptDefinition;
import com.mcpscanner.mcp.PromptArgument;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.stream.IntStream;

import static org.assertj.core.api.Assertions.assertThat;

class PromptTablePanelTest {

    private final PromptTablePanel panel = new PromptTablePanel();

    @Test
    void populateSetsRowCount() {
        panel.populate(createPrompts(3));

        assertThat(panel.getTableModel().getRowCount()).isEqualTo(3);
    }

    @Test
    void populateWithEmptyListClearsRows() {
        panel.populate(createPrompts(2));
        panel.populate(List.of());

        assertThat(panel.getTableModel().getRowCount()).isZero();
    }

    @Test
    void populateDefaultsAllRowsToSelected() {
        List<McpPromptDefinition> prompts = createPrompts(3);

        panel.populate(prompts);

        assertThat(panel.selectedPrompts()).isEqualTo(prompts);
    }

    @Test
    void deselectingRowExcludesItFromSelectedPrompts() {
        List<McpPromptDefinition> prompts = createPrompts(3);
        panel.populate(prompts);

        panel.getTableModel().setValueAt(false, 2, 0);

        assertThat(panel.selectedPrompts())
                .containsExactly(prompts.get(0), prompts.get(1));
    }

    @Test
    void selectingRowPopulatesDetailPanel() {
        McpPromptDefinition prompt = new McpPromptDefinition(
                "summarize",
                "summarise text",
                List.of(new PromptArgument("text", "input body", true)));
        panel.populate(List.of(prompt));

        panel.getTableForTest().setRowSelectionInterval(0, 0);

        PromptTablePanel.PromptDetailPanel detail = panel.getDetailPanelForTest();
        assertThat(detail.nameLabelForTest().getText()).isEqualTo("summarize");
        assertThat(detail.descriptionAreaForTest().getText()).isEqualTo("summarise text");
        assertThat(detail.argumentsModelForTest().getRowCount()).isEqualTo(1);
        assertThat(detail.argumentsModelForTest().getValueAt(0, 0)).isEqualTo("text");
        assertThat(detail.argumentsModelForTest().getValueAt(0, 2)).isEqualTo(Boolean.TRUE);
    }

    private List<McpPromptDefinition> createPrompts(int count) {
        return IntStream.range(0, count)
                .mapToObj(i -> new McpPromptDefinition(
                        "p" + i, "desc " + i, List.of()))
                .toList();
    }
}
