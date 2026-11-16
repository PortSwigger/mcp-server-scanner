package com.mcpscanner.scan;

import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.scanner.audit.insertionpoint.AuditInsertionPoint;
import burp.api.montoya.scanner.audit.insertionpoint.AuditInsertionPointProvider;
import com.mcpscanner.mcp.BurpNativeJsonRpcFields;
import com.mcpscanner.mcp.McpRequestDetector;
import com.mcpscanner.scan.field.ClientMetadataFieldGenerator;
import com.mcpscanner.scan.field.AddedArgumentRegistry;
import com.mcpscanner.scan.field.McpFieldGenerator;
import com.mcpscanner.scan.field.TemplateExpansionRegistry;

import java.util.List;
import java.util.function.BooleanSupplier;

public class McpInsertionPointProvider implements AuditInsertionPointProvider {

    private final McpFieldGenerator fieldGenerator;
    private final ClientMetadataFieldGenerator clientMetadataFields = new ClientMetadataFieldGenerator();

    public McpInsertionPointProvider() {
        this(() -> true);
    }

    public McpInsertionPointProvider(BooleanSupplier headerFieldsEnabled) {
        this(headerFieldsEnabled, new TemplateExpansionRegistry(), BurpNativeJsonRpcFields.ABSENT);
    }

    public McpInsertionPointProvider(BooleanSupplier headerFieldsEnabled, TemplateExpansionRegistry templateExpansions,
                                     BurpNativeJsonRpcFields burpNativeFields) {
        this(headerFieldsEnabled, templateExpansions, burpNativeFields, new AddedArgumentRegistry());
    }

    public McpInsertionPointProvider(BooleanSupplier headerFieldsEnabled, TemplateExpansionRegistry templateExpansions,
                                     BurpNativeJsonRpcFields burpNativeFields, AddedArgumentRegistry addedArguments) {
        this.fieldGenerator = new McpFieldGenerator(headerFieldsEnabled, templateExpansions, burpNativeFields,
                addedArguments);
    }

    @Override
    public List<AuditInsertionPoint> provideInsertionPoints(HttpRequestResponse baseHttpRequestResponse) {
        if (!McpRequestDetector.classify(baseHttpRequestResponse).isMcp()) {
            return clientMetadataFields.fieldsOf(baseHttpRequestResponse.request());
        }
        return fieldGenerator.fieldsOf(baseHttpRequestResponse.request());
    }
}
