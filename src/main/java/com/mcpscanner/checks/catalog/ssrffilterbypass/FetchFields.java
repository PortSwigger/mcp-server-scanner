package com.mcpscanner.checks.catalog.ssrffilterbypass;

import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.scanner.audit.insertionpoint.AuditInsertionPoint;
import com.mcpscanner.checks.shared.fetch.OutboundFetchPurpose;
import com.mcpscanner.checks.shared.field.InsertionPointNames;
import com.mcpscanner.checks.shared.jsonrpc.JsonRpcEnvelope;
import com.mcpscanner.mcp.BurpNativeJsonRpcFields;

import java.util.Optional;

final class FetchFields {

    private static final String EXTENSION_FIELD = "MCP field: ";

    private final OutboundFetchPurpose purpose = new OutboundFetchPurpose();
    private final InsertionPointNames names;

    FetchFields(BurpNativeJsonRpcFields burpNativeFields) {
        this.names = new InsertionPointNames(burpNativeFields);
    }

    Optional<FetchField> of(HttpRequest request, AuditInsertionPoint point) {
        JsonRpcEnvelope envelope = JsonRpcEnvelope.of(request.body().getBytes());
        Optional<String> method = envelope.method().filter(ignored -> envelope.declaresJsonRpcVersion());
        Optional<String> operation = envelope.paramsName();
        return method.flatMap(called -> fieldName(request, point)
                .filter(name -> purpose.fetchesByDesign(called, operation, name))
                .map(name -> new FetchField(name, called + " " + operation.orElse(""))));
    }

    private Optional<String> fieldName(HttpRequest request, AuditInsertionPoint point) {
        return Optional.ofNullable(point.name()).filter(name -> name.startsWith(EXTENSION_FIELD))
                .or(() -> names.burpArgumentNameOf(request, point));
    }
}
