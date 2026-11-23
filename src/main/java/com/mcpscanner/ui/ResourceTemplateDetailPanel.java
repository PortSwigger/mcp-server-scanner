package com.mcpscanner.ui;

import com.mcpscanner.mcp.McpResourceTemplateDefinition;
import com.mcpscanner.ui.completion.CompletionMenus;
import com.mcpscanner.ui.detail.DetailTabs;
import com.mcpscanner.ui.detail.uri.UriTemplateOverview;

import javax.swing.JComponent;
import javax.swing.JPanel;

final class ResourceTemplateDetailPanel extends AbstractDetailPanel<McpResourceTemplateDefinition> {

    private static final String COMPLETIONS_CAPABILITY = "completions";

    private JComponent overview = new JPanel();
    private CompletionMenus completionMenus = CompletionMenus.none();

    ResourceTemplateDetailPanel(DetailSubject<McpResourceTemplateDefinition> subject, InventoryTicks ticks) {
        super(subject, ticks);
        installDetailCard();
    }

    @Override
    protected void showTabs(McpResourceTemplateDefinition template, DetailTabs tabs) {
        overview = UriTemplateOverview.of(template.uriTemplate(), template.mimeType(), template.description(),
                raw(template), session().capabilities().containsKey(COMPLETIONS_CAPABILITY),
                completionMenus.forTemplateVariables(template.uriTemplate()));
        tabs.add("Overview", overview);
    }

    void bindCompletion(CompletionMenus menus) {
        completionMenus = menus;
    }

    JComponent overview() {
        return overview;
    }
}
