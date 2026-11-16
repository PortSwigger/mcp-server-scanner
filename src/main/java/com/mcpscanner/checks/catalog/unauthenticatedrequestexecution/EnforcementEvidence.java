package com.mcpscanner.checks.catalog.unauthenticatedrequestexecution;

import burp.api.montoya.http.message.HttpRequestResponse;
import com.mcpscanner.checks.api.HostKey;
import com.mcpscanner.checks.shared.auth.oracle.BaselineEquivalenceOracle;
import com.mcpscanner.checks.shared.probe.ProbeExchange;
import com.mcpscanner.checks.shared.probe.ServerErrorAnswer;
import com.mcpscanner.checks.shared.scancontext.CurrentInvocation;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ConcurrentHashMap;

final class EnforcementEvidence {

    private final BaselineEquivalenceOracle oracle;
    private final Map<HostKey, HttpRequestResponse> refusals = new ConcurrentHashMap<>();
    private final Map<HostKey, CompletableFuture<Optional<HttpRequestResponse>>> probes = new ConcurrentHashMap<>();

    private final List<CurrentInvocation.Retention> retentions = new ArrayList<>();
    private int generation;

    EnforcementEvidence(BaselineEquivalenceOracle oracle) {
        this.oracle = oracle;
    }

    void recordRefusal(AuditSubject subject, ProbeExchange refusal) {
        if (oracle.successful(subject.baseline()) && !ServerErrorAnswer.of(refusal.last())) {
            if (refusals.putIfAbsent(subject.host(), refusal.last()) == null) {
                retainBeyondInvocation(currentGeneration());
            }
        }
    }

    Optional<HttpRequestResponse> find(AuditSubject subject, EnforcementProbe probe) {
        HostKey host = subject.host();
        Optional<HttpRequestResponse> refusal = Optional.ofNullable(refusals.get(host));
        return refusal.isPresent() ? refusal : probed(subject, probe).or(() -> Optional.ofNullable(refusals.get(host)));
    }

    void clear() {
        List<CurrentInvocation.Retention> dropped;
        synchronized (this) {
            generation++;
            refusals.clear();
            probes.clear();
            dropped = List.copyOf(retentions);
            retentions.clear();
        }
        dropped.forEach(CurrentInvocation.Retention::release);
    }

    private synchronized int currentGeneration() {
        return generation;
    }

    private void retainBeyondInvocation(int observedGeneration) {
        CurrentInvocation.Retention retention = CurrentInvocation.retainingBeyondInvocation();
        synchronized (this) {
            if (observedGeneration == generation) {
                retentions.add(retention);
                return;
            }
        }
        retention.release();
    }

    private Optional<HttpRequestResponse> probed(AuditSubject subject, EnforcementProbe probe) {
        CompletableFuture<Optional<HttpRequestResponse>> claim = new CompletableFuture<>();
        CompletableFuture<Optional<HttpRequestResponse>> running = probes.putIfAbsent(subject.host(), claim);
        if (running != null) {
            return running.join();
        }
        try {
            int startedIn = currentGeneration();
            Optional<HttpRequestResponse> observed = probe.observe(subject);
            observed.ifPresent(exchange -> retainBeyondInvocation(startedIn));
            claim.complete(observed);
        } catch (RuntimeException failure) {
            probes.remove(subject.host(), claim);
            claim.complete(Optional.empty());
        }
        return claim.join();
    }
}
