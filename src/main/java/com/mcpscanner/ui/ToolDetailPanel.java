package com.mcpscanner.ui;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.MissingNode;
import com.mcpscanner.mcp.McpObjectMapper;
import com.mcpscanner.mcp.McpToolDefinition;
import com.mcpscanner.ui.detail.DeclaredTitle;
import com.mcpscanner.ui.detail.DetailTabs;
import com.mcpscanner.ui.detail.schema.SchemaTable;
import com.mcpscanner.ui.widgets.ScrollableForm;
import com.mcpscanner.ui.widgets.WrappingText;

import javax.swing.BorderFactory;
import javax.swing.JComponent;
import java.util.List;
import java.util.Optional;

final class ToolDetailPanel extends AbstractDetailPanel<McpToolDefinition> {

    private static final String ARGUMENTS_HINT =
            "Scans call this tool with default arguments built from its input schema. To edit them, use Send to › Repeater.";

    private final SchemaTable parameters = new SchemaTable("Arguments object");
    private final SchemaTable outputSchema = new SchemaTable("Output object");
    private final ToolDetailsTab details = new ToolDetailsTab();
    private final JComponent parametersTab = ScrollableForm.wrap(parameters);
    private final JComponent outputSchemaTab = ScrollableForm.wrap(outputSchema);
    private final JComponent detailsTab = ScrollableForm.wrap(details);
    private final Optional<JComponent> argumentsHint;
    private final JComponent descriptionTab;

    ToolDetailPanel() {
        this(InventoryTicks.SCAN_SELECTION);
    }

    ToolDetailPanel(InventoryTicks ticks) {
        super(new DetailSubject<>("tool", McpToolDefinition::name, McpToolDefinition::description,
                McpToolDefinition::raw, "tools/list"), ticks);
        argumentsHint = ticks.ifScanning(ToolDetailPanel::buildArgumentsHint);
        descriptionTab = ScrollableForm.wrapAtTop(description());
        installDetailCard(argumentsHint.stream().toArray(JComponent[]::new));
    }

    @Override
    protected void showTabs(McpToolDefinition tool, DetailTabs tabs) {
        tabs.addWhen(description().hasContent(), "Description", descriptionTab);
        addParametersTab(tool, tabs);
        addOutputSchemaTab(raw(tool).path("outputSchema"), tabs);
        details.show(raw(tool));
        tabs.addWhen(details.hasContent(), "Details", detailsTab);
    }

    @Override
    protected List<JComponent> headerLine(McpToolDefinition tool) {
        return ToolBehaviourChips.of(tool);
    }

    @Override
    protected Optional<String> titleOf(McpToolDefinition tool) {
        JsonNode raw = raw(tool);
        return DeclaredTitle.firstOf(raw.path("title"), raw.path("annotations").path("title"));
    }

    SchemaTable parametersTable() {
        return parameters;
    }

    SchemaTable outputSchemaTable() {
        return outputSchema;
    }

    ToolDetailsTab detailsView() {
        return details;
    }

    JComponent argumentsHint() {
        return argumentsHint.orElseThrow();
    }

    private void addParametersTab(McpToolDefinition tool, DetailTabs tabs) {
        parameters.show(inputSchemaOf(tool), session().protocolVersion());
        boolean declaresParameters = parameters.hasContent();
        argumentsHint.ifPresent(hint -> hint.setVisible(declaresParameters));
        tabs.addWhen(declaresParameters, "Parameters (" + parameters.parameterCount() + ")", parametersTab);
    }

    private void addOutputSchemaTab(JsonNode schema, DetailTabs tabs) {
        if (schema.isObject()) {
            outputSchema.show(schema, session().protocolVersion());
            tabs.add("Output schema", outputSchemaTab);
        }
    }

    private JsonNode inputSchemaOf(McpToolDefinition tool) {
        JsonNode declared = raw(tool).path("inputSchema");
        return declared.isObject() ? declared : parsed(tool.inputSchema());
    }

    private static JsonNode parsed(String schema) {
        if (schema == null || schema.isBlank()) {
            return MissingNode.getInstance();
        }
        try {
            return McpObjectMapper.INSTANCE.readTree(schema);
        } catch (JsonProcessingException ex) {
            return MissingNode.getInstance();
        }
    }

    private static JComponent buildArgumentsHint() {
        WrappingText hint = new WrappingText(ARGUMENTS_HINT).muted();
        hint.setBorder(BorderFactory.createEmptyBorder(4, 0, 0, 0));
        return hint;
    }
}
