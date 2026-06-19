package com.mcpscanner.ui;

import com.mcpscanner.mcp.McpPromptDefinition;
import com.mcpscanner.mcp.PromptArgument;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.stream.IntStream;

import static org.assertj.core.api.Assertions.assertThat;

class PromptTableModelTest {

    private final PromptTableModel model = new PromptTableModel();

    @Test
    void populateAddsRows() {
        model.populate(createPrompts(3));

        assertThat(model.getRowCount()).isEqualTo(3);
    }

    @Test
    void populateReplacesPreviousRows() {
        model.populate(createPrompts(4));
        model.populate(createPrompts(1));

        assertThat(model.getRowCount()).isEqualTo(1);
    }

    @Test
    void columnNamesMatch() {
        assertThat(model.getColumnCount()).isEqualTo(4);
        assertThat(model.getColumnName(0)).isEqualTo("Select");
        assertThat(model.getColumnName(1)).isEqualTo("Name");
        assertThat(model.getColumnName(2)).isEqualTo("Description");
        assertThat(model.getColumnName(3)).isEqualTo("Arguments");
    }

    @Test
    void getValueAtRendersRequiredArgumentsWithStar() {
        McpPromptDefinition prompt = new McpPromptDefinition(
                "summarize",
                "summarise a body of text",
                List.of(
                        new PromptArgument("text", "input", true),
                        new PromptArgument("locale", "language", false)));

        model.populate(List.of(prompt));

        assertThat(model.getValueAt(0, 0)).isEqualTo(Boolean.TRUE);
        assertThat(model.getValueAt(0, 1)).isEqualTo("summarize");
        assertThat(model.getValueAt(0, 2)).isEqualTo("summarise a body of text");
        assertThat(model.getValueAt(0, 3)).isEqualTo("text*, locale");
    }

    @Test
    void getValueAtReturnsEmptyStringForNoArguments() {
        McpPromptDefinition prompt = new McpPromptDefinition("greet", "say hi", List.of());
        model.populate(List.of(prompt));

        assertThat(model.getValueAt(0, 3)).isEqualTo("");
    }

    @Test
    void onlySelectColumnIsEditable() {
        model.populate(createPrompts(1));

        assertThat(model.isCellEditable(0, 0)).isTrue();
        for (int column = 1; column < model.getColumnCount(); column++) {
            assertThat(model.isCellEditable(0, column)).isFalse();
        }
    }

    @Test
    void populateDefaultsAllRowsToSelected() {
        List<McpPromptDefinition> prompts = createPrompts(3);
        model.populate(prompts);

        assertThat(model.selectedItems()).isEqualTo(prompts);
    }

    @Test
    void deselectingRowExcludesItFromSelectedItems() {
        List<McpPromptDefinition> prompts = createPrompts(3);
        model.populate(prompts);

        model.setValueAt(false, 0, 0);

        assertThat(model.selectedItems())
                .containsExactly(prompts.get(1), prompts.get(2));
    }

    @Test
    void rowAtReturnsRow() {
        List<McpPromptDefinition> prompts = createPrompts(2);
        model.populate(prompts);

        assertThat(model.rowAt(0)).isEqualTo(prompts.get(0));
        assertThat(model.rowAt(1)).isEqualTo(prompts.get(1));
    }

    @Test
    void rowAtOutOfBoundsReturnsNull() {
        model.populate(createPrompts(1));

        assertThat(model.rowAt(-1)).isNull();
        assertThat(model.rowAt(5)).isNull();
    }

    private List<McpPromptDefinition> createPrompts(int count) {
        return IntStream.range(0, count)
                .mapToObj(i -> new McpPromptDefinition(
                        "p" + i, "desc " + i, List.of(new PromptArgument("a" + i, "", false))))
                .toList();
    }
}
