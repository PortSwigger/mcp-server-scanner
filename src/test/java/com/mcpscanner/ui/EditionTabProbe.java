package com.mcpscanner.ui;

import com.mcpscanner.client.ConnectResult;
import com.mcpscanner.mcp.McpPromptDefinition;
import com.mcpscanner.mcp.McpResourceDefinition;
import com.mcpscanner.mcp.McpResourceTemplateDefinition;
import com.mcpscanner.mcp.PromptArgument;
import com.mcpscanner.mcp.ServerMetadata;
import com.mcpscanner.testutil.SwingTree;
import com.mcpscanner.ui.sendto.SendToDestination;
import com.mcpscanner.ui.widgets.SideDrawer;

import javax.swing.AbstractButton;
import javax.swing.JLabel;
import javax.swing.JMenuItem;
import javax.swing.JTable;
import javax.swing.table.TableColumn;
import javax.swing.text.JTextComponent;
import java.awt.Component;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Optional;
import java.util.stream.Stream;

import static com.mcpscanner.ui.McpScannerTabFixture.drawer;
import static com.mcpscanner.ui.McpScannerTabFixture.fromEdt;
import static com.mcpscanner.ui.McpScannerTabFixture.onEdt;
import static com.mcpscanner.ui.McpScannerTabFixture.prompts;
import static com.mcpscanner.ui.McpScannerTabFixture.resources;
import static com.mcpscanner.ui.McpScannerTabFixture.templates;
import static com.mcpscanner.ui.McpScannerTabFixture.tools;

final class EditionTabProbe {

    static final String EDITION_UI = "edition-ui";

    private EditionTabProbe() {
    }

    static ConnectResult oneItemOfEachKind() {
        return new ConnectResult(List.of(McpScannerTabFixture.readOnlyTool("echo")),
                List.of(new McpResourceDefinition("file:///a", "a", "", "text/plain")),
                List.of(new McpResourceTemplateDefinition("file:///{path}", "files", "", "text/plain")),
                List.of(new McpPromptDefinition("summary", "", List.of(new PromptArgument("topic", "", true)))),
                ServerMetadata.empty());
    }

    static List<Component> everyComponentInEverySection(McpScannerTab tab) throws Exception {
        return fromEdt(() -> {
            inventoryTables(tab).forEach(table -> table.setRowSelectionInterval(0, 0));
            SideDrawer drawer = drawer(tab);
            List<Component> found = new ArrayList<>(SwingTree.descendants(tab));
            for (String section : drawer.sectionOrder()) {
                drawer.expand(section);
                found.addAll(SwingTree.descendants(tab));
            }
            return found;
        });
    }

    static List<String> texts(List<Component> components) {
        return components.stream().map(EditionTabProbe::textOf).flatMap(Optional::stream).toList();
    }

    static boolean isLabelled(String text, String label) {
        return text.equals(label) || text.startsWith(label + " ") || text.startsWith(label + "…")
                || text.startsWith(label + " ▾");
    }

    static List<Integer> tickBoxColumnsOf(AbstractInventoryTablePanel<?, ?> panel) {
        return Collections.list(panel.table().getColumnModel().getColumns()).stream()
                .map(TableColumn::getModelIndex)
                .filter(index -> index == SelectableInventoryTableModel.SELECT_COLUMN_INDEX).toList();
    }

    static Stream<AbstractInventoryTablePanel<?, ?>> tickableInventoryPanels(McpScannerTab tab) {
        return Stream.of(tools(tab), resources(tab), prompts(tab));
    }

    static List<String> toolRowMenuTexts(McpScannerTab tab) throws Exception {
        onEdt(() -> tab.setSendToDestinations(List.of(SendToDestination.of("Repeater", (request, title) -> { }),
                SendToDestination.of("Organizer", (request, title) -> { }))));
        return fromEdt(() -> Arrays.stream(tools(tab).rowMenu(0).getComponents())
                .filter(JMenuItem.class::isInstance).map(item -> ((JMenuItem) item).getText()).toList());
    }

    static Optional<String> promptArgumentMenuLabel(McpScannerTab tab) throws Exception {
        return fromEdt(() -> {
            PromptTablePanel.PromptDetailPanel detail = prompts(tab).detailPanel();
            detail.show(prompts(tab).getTableModel().rowAt(0));
            return PopupProbe.rightClickLabel(detail.argumentsView().grid().rows().get(0).argument(), 1, 1);
        });
    }

    private static Stream<JTable> inventoryTables(McpScannerTab tab) {
        return Stream.of(tools(tab).table(), resources(tab).table(), templates(tab).table(), prompts(tab).table());
    }

    private static Optional<String> textOf(Component component) {
        if (component instanceof AbstractButton button) {
            return Optional.ofNullable(button.getText());
        }
        if (component instanceof JLabel label) {
            return Optional.ofNullable(label.getText());
        }
        if (component instanceof JTextComponent text && !text.isEditable()) {
            return Optional.ofNullable(text.getText());
        }
        return Optional.empty();
    }
}
