package com.mcpscanner;

import burp.api.montoya.core.ByteArray;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.scanner.audit.insertionpoint.AuditInsertionPoint;
import com.mcpscanner.checks.registry.ProbeCalls;
import com.mcpscanner.mcp.JsonLeaf;
import com.mcpscanner.mcp.JsonLeafLocator;
import com.mcpscanner.mcp.JsonStep;
import com.mcpscanner.scan.ArgumentPath;
import com.mcpscanner.scan.field.AddedArgumentRegistry;

import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.stream.Collectors;

final class AddedLeafProbeCalls implements ProbeCalls {

    private static final String MARKER = "mcp-scanner-leaf-marker";

    private final AddedArgumentRegistry addedArguments;

    AddedLeafProbeCalls(AddedArgumentRegistry addedArguments) {
        this.addedArguments = Objects.requireNonNull(addedArguments);
    }

    @Override
    public boolean include(HttpRequestResponse base) {
        return addedArguments.isProbe(base.request().bodyToString());
    }

    @Override
    public boolean fuzzesAddedLeaf(HttpRequestResponse base, AuditInsertionPoint insertionPoint) {
        return addedArguments.addedTo(base.request().bodyToString())
                .map(ArgumentPath::stepsInRequest)
                .map(added -> leavesChangedBy(base, insertionPoint).equals(Set.of(added)))
                .orElse(true);
    }

    private static Set<List<JsonStep>> leavesChangedBy(HttpRequestResponse base, AuditInsertionPoint insertionPoint) {
        byte[] original = base.request().body().getBytes();
        byte[] altered = insertionPoint.buildHttpRequestWithPayload(ByteArray.byteArray(MARKER)).body().getBytes();
        Map<List<JsonStep>, String> before = valuesByPath(original);
        return valuesByPath(altered).entrySet().stream()
                .filter(leaf -> !leaf.getValue().equals(before.get(leaf.getKey())))
                .map(Map.Entry::getKey)
                .collect(Collectors.toSet());
    }

    private static Map<List<JsonStep>, String> valuesByPath(byte[] body) {
        Map<List<JsonStep>, String> values = new HashMap<>();
        for (JsonLeaf leaf : JsonLeafLocator.paramsLeaves(body)) {
            values.put(leaf.steps(), leaf.kind() + ":" + new String(body, leaf.startInclusive(), leaf.endExclusive() - leaf.startInclusive(), StandardCharsets.UTF_8));
        }
        return values;
    }
}
