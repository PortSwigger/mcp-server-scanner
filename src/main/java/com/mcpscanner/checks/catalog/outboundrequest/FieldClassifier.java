package com.mcpscanner.checks.catalog.outboundrequest;

import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.scanner.audit.insertionpoint.AuditInsertionPoint;

import com.mcpscanner.checks.shared.fetch.OutboundFetchPurpose;
import com.mcpscanner.checks.shared.field.InsertionPointNames;
import com.mcpscanner.mcp.BurpNativeJsonRpcFields;

import java.util.Optional;
import java.util.regex.Pattern;

final class FieldClassifier {

    private static final Pattern EXTENSION_FIELD = Pattern.compile("^MCP (?:field|header|template variable): ");
    private static final Pattern CLIENT_METADATA = Pattern.compile("^MCP field: params\\.(?:_meta\\.\\S*/)?clientInfo\\.");
    private static final Pattern OPERATION_SPECIFIC = Pattern.compile(
            "^MCP (?:field: params\\.arguments[.\\[]|template variable: )");

    private final OutboundFetchPurpose fetchPurpose = new OutboundFetchPurpose();
    private final InsertionPointNames insertionPointNames;

    FieldClassifier(BurpNativeJsonRpcFields burpNativeFields) {
        this.insertionPointNames = new InsertionPointNames(burpNativeFields);
    }

    Optional<ProbedField> classify(HttpRequest request, AuditInsertionPoint point) {
        Optional<McpEnvelope> envelope = McpEnvelope.of(request.body().getBytes());
        if (envelope.isPresent()) {
            return mcpFieldName(request, point).map(name -> mcpField(envelope.get(), name));
        }
        return oauthField(request, point);
    }

    private Optional<String> mcpFieldName(HttpRequest request, AuditInsertionPoint point) {
        return Optional.ofNullable(point.name()).filter(name -> EXTENSION_FIELD.matcher(name).find())
                .or(() -> insertionPointNames.burpArgumentNameOf(request, point));
    }

    private ProbedField mcpField(McpEnvelope envelope, String fieldName) {
        String request = envelope.describe();
        Optional<String> operation = Optional.of(request).filter(ignored -> isOperationSpecific(fieldName));
        return new ProbedField(mcpCategory(envelope, fieldName), fieldName, operation, request);
    }

    private static boolean isOperationSpecific(String fieldName) {
        return OPERATION_SPECIFIC.matcher(fieldName).find();
    }

    private FieldCategory mcpCategory(McpEnvelope envelope, String fieldName) {
        if (CLIENT_METADATA.matcher(fieldName).find()) {
            return FieldCategory.CLIENT_METADATA;
        }
        return fetchPurpose.fetchesByDesign(envelope.method(), envelope.target(), fieldName) ? FieldCategory.FETCH_BY_DESIGN
                : FieldCategory.REQUEST_FIELD;
    }

    private static Optional<ProbedField> oauthField(HttpRequest request, AuditInsertionPoint point) {
        if (!OAuthClientFields.isFetchedUrlField(request, point.name())) {
            return Optional.empty();
        }
        String endpoint = request.method() + " " + pathOf(request);
        return Optional.of(new ProbedField(FieldCategory.OAUTH_CLIENT_METADATA, "OAuth parameter " + point.name(),
                Optional.of(endpoint), endpoint));
    }

    private static String pathOf(HttpRequest request) {
        String path = request.path();
        int query = path.indexOf('?');
        return query < 0 ? path : path.substring(0, query);
    }
}
