package com.mcpscanner;

import burp.api.montoya.core.ByteArray;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.scanner.audit.insertionpoint.AuditInsertionPoint;
import burp.api.montoya.scanner.audit.insertionpoint.AuditInsertionPointType;
import com.mcpscanner.checks.registry.ProbeCalls;
import com.mcpscanner.mcp.JsonLeaf;
import com.mcpscanner.mcp.JsonLeafLocator;
import com.mcpscanner.mcp.JsonStep;
import com.mcpscanner.scan.ArgumentPath;
import com.mcpscanner.scan.field.AddedArgumentRegistry;
import com.mcpscanner.scan.field.MetaEnvelope;
import com.mcpscanner.scan.field.MetaEnvelopeRegistry;

import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.function.BiPredicate;
import java.util.stream.Collectors;

final class ScannedLeaves implements ProbeCalls {

    private static final String MARKER = "mcp-scanner-leaf-marker";

    private final AddedArgumentRegistry addedArguments;
    private final MetaEnvelopeRegistry metaEnvelopes;
    private final BiPredicate<HttpRequest, HttpRequest> proxyDropsEveryChange;

    ScannedLeaves(AddedArgumentRegistry addedArguments, MetaEnvelopeRegistry metaEnvelopes,
                  BiPredicate<HttpRequest, HttpRequest> proxyDropsEveryChange) {
        this.addedArguments = Objects.requireNonNull(addedArguments);
        this.metaEnvelopes = Objects.requireNonNull(metaEnvelopes);
        this.proxyDropsEveryChange = Objects.requireNonNull(proxyDropsEveryChange);
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

    @Override
    public boolean isPassengerMetaEnvelopePoint(HttpRequestResponse base, AuditInsertionPoint insertionPoint) {
        if (insertionPoint.type() == AuditInsertionPointType.HEADER
                || metaEnvelopes.fuzzesEnvelopeOf(base.request().bodyToString())) {
            return false;
        }
        Set<List<JsonStep>> changed = leavesChangedBy(base, insertionPoint);
        return !changed.isEmpty() && changed.stream().allMatch(MetaEnvelope::contains);
    }

    @Override
    public boolean fuzzesOnlyWhatTheProxyDrops(HttpRequestResponse base, AuditInsertionPoint insertionPoint) {
        return proxyDropsEveryChange.test(base.request(), markedRequest(insertionPoint));
    }

    private static Set<List<JsonStep>> leavesChangedBy(HttpRequestResponse base, AuditInsertionPoint insertionPoint) {
        byte[] original = base.request().body().getBytes();
        byte[] altered = markedRequest(insertionPoint).body().getBytes();
        Map<List<JsonStep>, String> before = valuesByPath(original);
        return valuesByPath(altered).entrySet().stream()
                .filter(leaf -> !leaf.getValue().equals(before.get(leaf.getKey())))
                .map(Map.Entry::getKey)
                .collect(Collectors.toSet());
    }

    private static HttpRequest markedRequest(AuditInsertionPoint insertionPoint) {
        return insertionPoint.buildHttpRequestWithPayload(ByteArray.byteArray(MARKER));
    }

    private static Map<List<JsonStep>, String> valuesByPath(byte[] body) {
        Map<List<JsonStep>, String> values = new HashMap<>();
        for (JsonLeaf leaf : JsonLeafLocator.paramsLeaves(body)) {
            values.put(leaf.steps(), leaf.kind() + ":" + new String(body, leaf.startInclusive(), leaf.endExclusive() - leaf.startInclusive(), StandardCharsets.UTF_8));
        }
        return values;
    }
}
