package com.mcpscanner.automation;

import burp.api.montoya.http.Http;
import burp.api.montoya.scanner.audit.issues.AuditIssue;
import com.mcpscanner.checks.registry.CheckInstrumentation;

import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;
import java.util.function.Supplier;
import java.util.stream.Collectors;

public final class CheckTelemetry implements CheckInstrumentation {

    private final ProbeCounter total;
    private final Supplier<ProbeCounter> newCounter;
    private final ConcurrentMap<String, ProbeCounter> probes = new ConcurrentHashMap<>();
    private final ConcurrentMap<String, Set<String>> checksByIssueName = new ConcurrentHashMap<>();

    public CheckTelemetry(ProbeCounter total, Supplier<ProbeCounter> newCounter) {
        this.total = total;
        this.newCounter = newCounter;
    }

    public static CheckTelemetry throughTheExtensionProxy() {
        return new CheckTelemetry(ProbeCounter.throughTheExtensionProxy(), ProbeCounter::throughTheExtensionProxy);
    }

    @Override
    public Http probeHttp(String checkId, Http http) {
        return total.wrapMarking(probes.computeIfAbsent(checkId, id -> newCounter.get()).wrap(http));
    }

    @Override
    public void reported(String checkId, List<AuditIssue> issues) {
        issues.forEach(issue -> checksByIssueName.computeIfAbsent(issue.name(), name -> ConcurrentHashMap.newKeySet())
                .add(checkId));
    }

    public List<String> checksReporting(String issueName) {
        return checksByIssueName.getOrDefault(issueName, Set.of()).stream().sorted().toList();
    }

    public Map<String, CheckProbes> probesByCheck() {
        return probes.entrySet().stream().collect(Collectors.toUnmodifiableMap(Map.Entry::getKey,
                entry -> new CheckProbes(entry.getValue().sent(), entry.getValue().reached())));
    }

    public int sent() {
        return total.sent();
    }

    public int reached() {
        return total.reached();
    }

    void reset() {
        total.reset();
        probes.clear();
        checksByIssueName.clear();
    }
}
