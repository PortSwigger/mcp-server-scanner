package com.mcpscanner.scan.field;

import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.scanner.audit.insertionpoint.AuditInsertionPoint;
import com.mcpscanner.mcp.BurpJsonRpcArguments;
import com.mcpscanner.mcp.BurpNativeJsonRpcFields;
import com.mcpscanner.mcp.JsonLeaf;
import com.mcpscanner.mcp.JsonLeafLocator;
import com.mcpscanner.mcp.JsonValueKind;
import com.mcpscanner.mcp.McpHeaders;
import com.mcpscanner.mcp.McpMethods;
import com.mcpscanner.mcp.McpObjectMapper;
import com.mcpscanner.scan.ArgumentPath;
import com.mcpscanner.scan.UriTemplateExpansion;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.function.BooleanSupplier;

public final class McpFieldGenerator {

    private static final String RESOURCE_URI_PATH = "params.uri";

    static final Set<String> UNFUZZED_HEADER_NAMES = Set.of(
            "host", "content-length", "content-type", "transfer-encoding", "connection", "keep-alive", "te",
            "upgrade", "expect", "accept", "accept-encoding", "accept-language", "user-agent", "origin", "referer",
            "authorization", "proxy-authorization", "cookie");

    private static final String SCANNER_SENTINEL_PREFIX = "x-mcp-scanner-";

    private final BooleanSupplier headerFieldsEnabled;
    private final TemplateExpansionRegistry templateExpansions;
    private final BurpNativeJsonRpcFields burpNativeFields;
    private final AddedArgumentRegistry addedArguments;

    public McpFieldGenerator(BooleanSupplier headerFieldsEnabled) {
        this(headerFieldsEnabled, new TemplateExpansionRegistry(), BurpNativeJsonRpcFields.ABSENT);
    }

    public McpFieldGenerator(BooleanSupplier headerFieldsEnabled, TemplateExpansionRegistry templateExpansions,
                             BurpNativeJsonRpcFields burpNativeFields) {
        this(headerFieldsEnabled, templateExpansions, burpNativeFields, new AddedArgumentRegistry());
    }

    public McpFieldGenerator(BooleanSupplier headerFieldsEnabled, TemplateExpansionRegistry templateExpansions,
                             BurpNativeJsonRpcFields burpNativeFields, AddedArgumentRegistry addedArguments) {
        this.headerFieldsEnabled = headerFieldsEnabled;
        this.templateExpansions = templateExpansions;
        this.burpNativeFields = burpNativeFields;
        this.addedArguments = addedArguments;
    }

    public List<AuditInsertionPoint> fieldsOf(HttpRequest request) {
        Optional<ArgumentPath> added = addedArguments.addedTo(request.bodyToString());
        if (added.isPresent()) {
            return addedArgumentField(request, added.get());
        }
        List<AuditInsertionPoint> fields = bodyFields(request);
        if (headerFieldsEnabled.getAsBoolean()) {
            fields.addAll(headerFields(request));
        }
        return fields;
    }

    private List<AuditInsertionPoint> addedArgumentField(HttpRequest request, ArgumentPath added) {
        byte[] body = request.body().getBytes();
        Optional<BurpJsonRpcArguments> burpArguments = burpNativeFields.argumentsIn(body);
        return JsonLeafLocator.paramsLeaves(body).stream()
                .filter(leaf -> leaf.steps().equals(added.stepsInRequest()))
                .filter(leaf -> !fuzzedByBurp(burpArguments, leaf))
                .<AuditInsertionPoint>map(leaf -> new JsonFieldInsertionPoint(request, leaf)).toList();
    }

    private List<AuditInsertionPoint> bodyFields(HttpRequest request) {
        byte[] body = request.body().getBytes();
        String method = methodOf(body);
        Optional<BurpJsonRpcArguments> burpArguments = burpNativeFields.argumentsIn(body);
        List<AuditInsertionPoint> fields = new ArrayList<>();
        for (JsonLeaf leaf : JsonLeafLocator.paramsLeaves(body)) {
            if (!fuzzedByBurp(burpArguments, leaf)) {
                fields.add(new JsonFieldInsertionPoint(request, leaf));
            }
            fields.addAll(templateVariableFields(request, body, method, leaf));
        }
        return fields;
    }

    private static boolean fuzzedByBurp(Optional<BurpJsonRpcArguments> burpArguments, JsonLeaf leaf) {
        return leaf.isScalar() && burpArguments.filter(arguments -> arguments.fuzzesScalarAt(leaf.steps())).isPresent();
    }

    private List<AuditInsertionPoint> templateVariableFields(HttpRequest request, byte[] body, String method,
                                                             JsonLeaf leaf) {
        if (!isResourceUri(method, leaf.path()) || !writtenVerbatim(body, leaf)) {
            return List.of();
        }
        List<UriTemplateExpansion.Variable> variables = templateExpansions.variablesIn(leaf.decodedValue());
        Map<String, Integer> occurrences = new HashMap<>();
        List<AuditInsertionPoint> fields = new ArrayList<>();
        for (UriTemplateExpansion.Variable variable : variables) {
            int occurrence = occurrences.merge(variable.name(), 1, Integer::sum);
            String label = occurrence == 1 ? variable.name() : variable.name() + " #" + occurrence;
            fields.add(new TemplateVariableInsertionPoint(request, leaf, variable, label));
        }
        return fields;
    }

    private static boolean isResourceUri(String method, String path) {
        return McpMethods.RESOURCES_READ.equals(method) && RESOURCE_URI_PATH.equals(path);
    }

    private static boolean writtenVerbatim(byte[] body, JsonLeaf leaf) {
        byte[] decoded = leaf.decodedValue().getBytes(StandardCharsets.UTF_8);
        return leaf.kind() == JsonValueKind.STRING
                && Arrays.equals(body, leaf.startInclusive() + 1, leaf.endExclusive() - 1, decoded, 0, decoded.length);
    }

    private static String methodOf(byte[] body) {
        try {
            return McpObjectMapper.INSTANCE.readTree(body).path("method").asText();
        } catch (IOException | RuntimeException e) {
            return "";
        }
    }

    private static List<AuditInsertionPoint> headerFields(HttpRequest request) {
        return request.headers().stream()
                .filter(header -> isFuzzable(header.name().toLowerCase(Locale.ROOT)))
                .<AuditInsertionPoint>map(header -> new McpHeaderInsertionPoint(request, header))
                .toList();
    }

    private static boolean isFuzzable(String headerName) {
        return !UNFUZZED_HEADER_NAMES.contains(headerName) && !headerName.startsWith(SCANNER_SENTINEL_PREFIX)
                && !McpHeaders.isParamHeader(headerName);
    }
}
