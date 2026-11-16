package com.mcpscanner;

import burp.api.montoya.MontoyaApi;
import com.mcpscanner.mcp.BurpNativeJsonRpcFields;
import com.mcpscanner.scan.McpInsertionPointProvider;
import com.mcpscanner.scan.ScanGenerationSettings;
import com.mcpscanner.scan.field.AddedArgumentRegistry;
import com.mcpscanner.scan.field.TemplateExpansionRegistry;

record ScanFieldWiring(ScanGenerationSettings generationSettings,
                       TemplateExpansionRegistry templateExpansions,
                       AddedArgumentRegistry addedArguments,
                       McpInsertionPointProvider everyField) {

    static ScanFieldWiring create(MontoyaApi api, ExtensionFoundation foundation) {
        ScanGenerationSettings generationSettings = new ScanGenerationSettings(foundation.configStore());
        TemplateExpansionRegistry templateExpansions = new TemplateExpansionRegistry();
        AddedArgumentRegistry addedArguments = new AddedArgumentRegistry();
        McpInsertionPointProvider everyField = new McpInsertionPointProvider(generationSettings::headerFieldsEnabled,
                templateExpansions, BurpNativeJsonRpcFields.ABSENT, addedArguments);
        api.scanner().registerInsertionPointProvider(new McpInsertionPointProvider(
                generationSettings::headerFieldsEnabled, templateExpansions, foundation.burpNativeFields(),
                addedArguments));
        return new ScanFieldWiring(generationSettings, templateExpansions, addedArguments, everyField);
    }
}
