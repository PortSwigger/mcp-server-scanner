package com.mcpscanner.ui;

import com.mcpscanner.mcp.McpToolDefinition;
import com.mcpscanner.mcp.ToolAnnotations;
import org.junit.jupiter.api.Test;

import javax.swing.JComponent;
import javax.swing.JList;
import javax.swing.ListCellRenderer;
import java.awt.Component;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

class DestructiveScanConfirmationTest {

    private static final ToolAnnotations READ_ONLY =
            new ToolAnnotations(null, true, null, null, null);
    private static final ToolAnnotations DESTRUCTIVE =
            new ToolAnnotations(null, false, true, null, null);

    @Test
    void requiresConfirmationWhenSelectionIncludesDestructiveTool() {
        List<McpToolDefinition> selected = List.of(
                tool("read", READ_ONLY),
                tool("destroy", DESTRUCTIVE));

        assertThat(DestructiveScanConfirmation.requiresConfirmation(selected, false))
                .isTrue();
    }

    @Test
    void requiresConfirmationWhenSelectionIncludesAnnotationsMissingTool() {
        List<McpToolDefinition> selected = List.of(
                tool("read", READ_ONLY),
                tool("unknown", ToolAnnotations.EMPTY));

        assertThat(DestructiveScanConfirmation.requiresConfirmation(selected, false))
                .isTrue();
    }

    @Test
    void noConfirmationWhenAllSelectedAreReadOnly() {
        List<McpToolDefinition> selected = List.of(
                tool("a", READ_ONLY),
                tool("b", READ_ONLY));

        assertThat(DestructiveScanConfirmation.requiresConfirmation(selected, false))
                .isFalse();
    }

    @Test
    void noConfirmationWhenDontAskAgainSet() {
        List<McpToolDefinition> selected = List.of(
                tool("destroy", DESTRUCTIVE));

        assertThat(DestructiveScanConfirmation.requiresConfirmation(selected, true))
                .isFalse();
    }

    @Test
    void nonReadOnlyReturnsOnlyDestructiveAndUnannotated() {
        McpToolDefinition read = tool("read", READ_ONLY);
        McpToolDefinition destroy = tool("destroy", DESTRUCTIVE);
        McpToolDefinition unknown = tool("unknown", ToolAnnotations.EMPTY);

        List<McpToolDefinition> result = DestructiveScanConfirmation.nonReadOnly(
                List.of(read, destroy, unknown));

        assertThat(result).containsExactly(destroy, unknown);
    }

    @Test
    void formatToolLineLabelsDestructive() {
        assertThat(DestructiveScanConfirmation.formatToolLine(tool("destroy", DESTRUCTIVE)))
                .isEqualTo("• destroy (destructive)");
    }

    @Test
    void formatToolLineLabelsAnnotationsMissing() {
        assertThat(DestructiveScanConfirmation.formatToolLine(tool("unknown", ToolAnnotations.EMPTY)))
                .isEqualTo("• unknown (annotations missing)");
    }

    @Test
    void toolLineRendererDisablesHtmlForUntrustedToolName() {
        McpToolDefinition tool = tool("<html><img src=x>", DESTRUCTIVE);
        ListCellRenderer<? super McpToolDefinition> renderer =
                DestructiveScanConfirmation.toolLineRendererForTest();
        JList<McpToolDefinition> list = new JList<>(new McpToolDefinition[] {tool});

        Component component = renderer.getListCellRendererComponent(list, tool, 0, false, false);

        assertThat(((JComponent) component).getClientProperty("html.disable"))
                .isEqualTo(Boolean.TRUE);
    }

    private static McpToolDefinition tool(String name, ToolAnnotations annotations) {
        return new McpToolDefinition(name, "desc", "{}", List.of(), annotations);
    }
}
