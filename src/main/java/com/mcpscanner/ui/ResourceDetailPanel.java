package com.mcpscanner.ui;

import com.mcpscanner.mcp.McpResourceDefinition;
import com.mcpscanner.ui.detail.DetailTabs;
import com.mcpscanner.ui.detail.uri.ResourceOverview;
import com.mcpscanner.ui.widgets.DetailLine;

import javax.swing.JComponent;
import javax.swing.JPanel;
import java.util.List;

final class ResourceDetailPanel extends AbstractDetailPanel<McpResourceDefinition> {

    private JComponent overview = new JPanel();

    ResourceDetailPanel(DetailSubject<McpResourceDefinition> subject, InventoryTicks ticks) {
        super(subject, ticks);
        installDetailCard();
    }

    @Override
    protected void showTabs(McpResourceDefinition resource, DetailTabs tabs) {
        overview = ResourceOverview.of(resource.uri(), resource.mimeType(), resource.description(), raw(resource));
        tabs.add("Overview", overview);
    }

    @Override
    protected List<JComponent> headerLine(McpResourceDefinition resource) {
        DetailLine uri = DetailLine.monospaced();
        uri.show(resource.uri());
        return uri.isVisible() ? List.of(uri) : List.of();
    }

    JComponent overview() {
        return overview;
    }
}
