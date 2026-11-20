package com.mcpscanner.ui;

import com.mcpscanner.client.ConnectResult;
import com.mcpscanner.mcp.ServerMetadata;
import com.mcpscanner.scan.McpRepeaterRequestFactory;
import com.mcpscanner.scan.ScanInventory;
import com.mcpscanner.scan.ScanMode;
import com.mcpscanner.scan.ScanTarget;
import com.mcpscanner.scan.request.AdvertisedAuthorizationServer;
import com.mcpscanner.scan.request.ServerCapabilities;
import com.mcpscanner.ui.completion.CompletionMenus;
import com.mcpscanner.ui.detail.DetailSession;
import com.mcpscanner.ui.sendto.SendToBinding;
import com.mcpscanner.ui.sendto.SendToMenu;
import com.mcpscanner.ui.sendto.SendToRequest;

import javax.swing.JTable;
import javax.swing.event.TableModelEvent;
import java.util.List;
import java.util.function.IntSupplier;
import java.util.function.Supplier;

final class InventoryPanels {

    private final InventoryTicks ticks;
    private final ToolTablePanel tools;
    private final ResourceTablePanel resources;
    private final ResourceTemplateTablePanel templates;
    private final PromptTablePanel prompts;
    private final ServerInfoPanel serverInfo = new ServerInfoPanel();
    private final List<AbstractInventoryTablePanel<?, ?>> all;
    private ServerCapabilities serverCapabilities = ServerCapabilities.none();
    private AdvertisedAuthorizationServer authorizationServer = AdvertisedAuthorizationServer.none();
    private DetailSession session = DetailSession.none();

    InventoryPanels() {
        this(InventoryTicks.SCAN_SELECTION);
    }

    InventoryPanels(InventoryTicks ticks) {
        this.ticks = ticks;
        this.tools = new ToolTablePanel(ticks);
        this.resources = new ResourceTablePanel(ticks);
        this.templates = new ResourceTemplateTablePanel(ticks);
        this.prompts = new PromptTablePanel(ticks);
        this.all = List.of(tools, resources, templates, prompts);
    }

    ToolTablePanel tools() {
        return tools;
    }

    ResourceTablePanel resources() {
        return resources;
    }

    ResourceTemplateTablePanel templates() {
        return templates;
    }

    PromptTablePanel prompts() {
        return prompts;
    }

    ServerInfoPanel serverInfo() {
        return serverInfo;
    }

    JTable focusTable() {
        return tools.table();
    }

    void addTo(InventoryTabs tabs) {
        addCounted(tabs, "Tools", tools, () -> tools.selectedTools().size());
        addCounted(tabs, "Resources", resources, () -> resources.selectedResources().size());
        addCounted(tabs, "Templates", templates, () -> templates.selectedResourceTemplates().size());
        addCounted(tabs, "Prompts", prompts, () -> prompts.selectedPrompts().size());
        tabs.addTab("Server Info", serverInfo);
        tabs.setSelectedIndex(0);
    }

    private void addCounted(InventoryTabs tabs, String title, AbstractInventoryTablePanel<?, ?> panel,
                            IntSupplier selected) {
        IntSupplier total = panel.getTableModel()::getRowCount;
        if (ticks.shown()) {
            tabs.addCounted(title, panel, selected, total);
        } else {
            tabs.addTitled(panel, () -> title + " (" + total.getAsInt() + ")");
        }
    }

    void bindSendTo(SendToMenu menu, McpRepeaterRequestFactory requests) {
        tools.setSendTo(new SendToBinding<>(menu,
                tool -> new SendToRequest("Tool: " + tool.name(), () -> requests.requestFor(new ScanTarget.Tool(tool)))));
        resources.setSendTo(new SendToBinding<>(menu,
                resource -> new SendToRequest("Resource: " + resource.name(), () -> requests.requestFor(new ScanTarget.Resource(resource)))));
        templates.setSendTo(new SendToBinding<>(menu, template -> new SendToRequest("Template: " + template.name(),
                () -> requests.requestFor(new ScanTarget.ResourceTemplate(template)))));
        prompts.setSendTo(new SendToBinding<>(menu,
                prompt -> new SendToRequest("Prompt: " + prompt.name(), () -> requests.requestFor(new ScanTarget.Prompt(prompt)))));
    }

    void bindCompletion(CompletionMenus menus) {
        templates.detailPanel().bindCompletion(menus);
        prompts.detailPanel().bindCompletion(menus);
    }

    void bindScans(InventoryScanner scanner, Supplier<ScanMode> mode) {
        tools.setScan(new ScanItemBinding<>(scanner, ScanTarget.Tool::new), mode);
        resources.setScan(new ScanItemBinding<>(scanner, ScanTarget.Resource::new), mode);
        templates.setScan(new ScanItemBinding<>(scanner, ScanTarget.ResourceTemplate::new), mode);
        prompts.setScan(new ScanItemBinding<>(scanner, ScanTarget.Prompt::new), mode);
    }

    void onSelectionChange(Runnable listener) {
        all.forEach(panel -> panel.getTableModel().addTableModelListener(event -> {
            if (event.getType() != TableModelEvent.UPDATE || event.getColumn() == 0) {
                listener.run();
            }
        }));
    }

    void populate(ConnectResult result) {
        tools.populate(result.toolsOutcome());
        resources.populate(result.resourcesOutcome());
        templates.populate(result.resourceTemplatesOutcome());
        prompts.populate(result.promptsOutcome());
        serverInfo.populate(result.serverMetadata());
        serverCapabilities = new ServerCapabilities(result.serverMetadata().capabilities());
        useSession(session.withCapabilities(result.serverMetadata().capabilities()));
    }

    void showConnection(ConnectionSummary connection) {
        serverInfo.showConnection(connection);
        useSession(session.withProtocolVersion(connection.protocolVersion()));
    }

    void clear() {
        populate(new ConnectResult(List.of(), List.of(), List.of(), List.of(), ServerMetadata.empty()));
        serverInfo.clearConnection();
        authorizationServer = AdvertisedAuthorizationServer.none();
        useSession(DetailSession.none());
    }

    private void useSession(DetailSession newSession) {
        session = newSession;
        all.forEach(panel -> panel.useSession(newSession));
    }

    ServerCapabilities serverCapabilities() {
        return serverCapabilities;
    }

    void advertise(AdvertisedAuthorizationServer server) {
        authorizationServer = server;
    }

    AdvertisedAuthorizationServer authorizationServer() {
        return authorizationServer;
    }

    void setAvailability(InventoryView.Availability availability) {
        all.forEach(panel -> panel.setAvailability(availability));
    }

    void refreshDetailActions() {
        all.forEach(AbstractInventoryTablePanel::refreshDetailActions);
    }

    ScanInventory selection() {
        return new ScanInventory(tools.selectedTools(), resources.selectedResources(),
                templates.selectedResourceTemplates(), prompts.selectedPrompts());
    }

    boolean isEmpty() {
        return all.stream().allMatch(panel -> panel.getTableModel().getRowCount() == 0);
    }
}
