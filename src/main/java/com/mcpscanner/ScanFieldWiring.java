package com.mcpscanner;

import burp.api.montoya.MontoyaApi;
import com.mcpscanner.logging.McpEventLog;
import com.mcpscanner.mcp.BurpNativeJsonRpcFields;
import com.mcpscanner.scan.McpInsertionPointProvider;
import com.mcpscanner.scan.ScanGenerationSettings;
import com.mcpscanner.scan.field.AddedArgumentRegistry;
import com.mcpscanner.scan.field.MetaEnvelopeRegistry;
import com.mcpscanner.scan.field.TemplateExpansionRegistry;

record ScanFieldWiring(ScanGenerationSettings generationSettings,
                       TemplateExpansionRegistry templateExpansions,
                       AddedArgumentRegistry addedArguments,
                       MetaEnvelopeRegistry metaEnvelopes,
                       McpInsertionPointProvider everyField,
                       BurpNativeJsonRpcFields burpNativeFields) {

    static ScanFieldWiring create(MontoyaApi api, ExtensionFoundation foundation) {
        ScanGenerationSettings generationSettings = new ScanGenerationSettings(foundation.configStore());
        TemplateExpansionRegistry templateExpansions = new TemplateExpansionRegistry();
        AddedArgumentRegistry addedArguments = new AddedArgumentRegistry();
        MetaEnvelopeRegistry metaEnvelopes = new MetaEnvelopeRegistry();
        BurpNativeJsonRpcFields burpNativeFields = burpNativeFields(api, foundation.eventLog());
        McpInsertionPointProvider everyField = new McpInsertionPointProvider(generationSettings::headerFieldsEnabled,
                templateExpansions, BurpNativeJsonRpcFields.ABSENT, addedArguments, metaEnvelopes);
        api.scanner().registerInsertionPointProvider(new McpInsertionPointProvider(
                generationSettings::headerFieldsEnabled, templateExpansions, burpNativeFields, addedArguments,
                metaEnvelopes));
        return new ScanFieldWiring(generationSettings, templateExpansions, addedArguments, metaEnvelopes, everyField,
                burpNativeFields);
    }

    private static BurpNativeJsonRpcFields burpNativeFields(MontoyaApi api, McpEventLog eventLog) {
        BurpNativeJsonRpcFields fields = BurpNativeJsonRpcFields.detectedIn(() -> api.burpSuite().version());
        eventLog.info(fields.present()
                ? "Burp fuzzes JSON-RPC arguments natively: Burp audits get only the MCP fields Burp leaves unfuzzed"
                : "Burp has no native JSON-RPC fields: Burp audits get every MCP field");
        return fields;
    }
}
