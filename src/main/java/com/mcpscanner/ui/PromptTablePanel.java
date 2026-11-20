package com.mcpscanner.ui;

import com.fasterxml.jackson.databind.JsonNode;
import com.mcpscanner.mcp.McpMethods;
import com.mcpscanner.mcp.McpPromptDefinition;
import com.mcpscanner.ui.completion.CompletionMenus;
import com.mcpscanner.ui.detail.DetailSection;
import com.mcpscanner.ui.detail.DetailTabs;
import com.mcpscanner.ui.detail.IconStrip;
import com.mcpscanner.ui.detail.MetaSection;
import com.mcpscanner.ui.widgets.ScrollableForm;

import javax.swing.Box;
import javax.swing.JComponent;
import javax.swing.JPanel;
import java.awt.BorderLayout;
import java.awt.Component;
import java.util.List;

public class PromptTablePanel
        extends AbstractInventoryTablePanel<McpPromptDefinition, PromptTablePanel.PromptDetailPanel> {

    public PromptTablePanel() {
        this(InventoryTicks.SCAN_SELECTION);
    }

    PromptTablePanel(InventoryTicks ticks) {
        super(ticks, List.of());
    }

    @Override
    protected SelectableInventoryTableModel<McpPromptDefinition> createTableModel() {
        return new PromptTableModel();
    }

    @Override
    protected String itemNoun() {
        return "prompt";
    }

    @Override
    protected String listMethod() {
        return McpMethods.PROMPTS_LIST;
    }

    @Override
    protected PromptDetailPanel createDetailPanel(InventoryTicks ticks) {
        return new PromptDetailPanel(ticks);
    }

    public List<McpPromptDefinition> selectedPrompts() {
        return getTableModel().selectedItems();
    }

    static final class PromptDetailPanel extends AbstractDetailPanel<McpPromptDefinition> {

        private static final int SECTION_GAP = 10;

        private final PromptArgumentsView argumentsView;
        private final JComponent argumentsTab;
        private final Box extras = Box.createVerticalBox();
        private final JPanel overview = new JPanel(new BorderLayout(0, SECTION_GAP));
        private final DetailSection iconsSection = new DetailSection("Icons");
        private final DetailSection metaSection = new DetailSection(MetaSection.TITLE);
        private CompletionMenus completionMenus = CompletionMenus.none();

        PromptDetailPanel() {
            this(InventoryTicks.SCAN_SELECTION);
        }

        PromptDetailPanel(InventoryTicks ticks) {
            super(new DetailSubject<>("prompt", McpPromptDefinition::name, McpPromptDefinition::description,
                    McpPromptDefinition::raw, McpMethods.PROMPTS_LIST), ticks);
            argumentsView = new PromptArgumentsView(ticks);
            argumentsTab = ScrollableForm.wrap(argumentsView);
            for (DetailSection section : List.of(iconsSection, metaSection)) {
                section.setAlignmentX(Component.LEFT_ALIGNMENT);
                extras.add(section);
            }
            overview.add(extras, BorderLayout.NORTH);
            overview.add(description(), BorderLayout.CENTER);
            installDetailCard();
        }

        @Override
        protected void showTabs(McpPromptDefinition prompt, DetailTabs tabs) {
            JsonNode raw = raw(prompt);
            showExtras(raw);
            List<PromptArgumentEntry> arguments = PromptArgumentEntry.listOf(prompt.arguments(), raw.path("arguments"));
            argumentsView.show(prompt.name(), arguments, completionMenus.forPromptArguments(prompt.name()));
            tabs.addWhen(overviewHasContent(), "Description", overview);
            tabs.add("Arguments (" + arguments.size() + ")", argumentsTab);
        }

        void bindCompletion(CompletionMenus menus) {
            completionMenus = menus;
        }

        PromptArgumentsView argumentsView() {
            return argumentsView;
        }

        JPanel overview() {
            return overview;
        }

        DetailSection metaSection() {
            return metaSection;
        }

        private void showExtras(JsonNode raw) {
            iconsSection.show(IconStrip.of(raw.path("icons")));
            metaSection.show(MetaSection.grid(raw.path("_meta")));
        }

        private boolean overviewHasContent() {
            return description().hasContent() || iconsSection.hasContent() || metaSection.hasContent();
        }
    }
}
