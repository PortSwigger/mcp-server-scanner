package com.mcpscanner.checks.catalog.originhostadmission;

import burp.api.montoya.http.message.HttpRequestResponse;
import com.mcpscanner.checks.api.HostSettlement;

import java.util.List;
import java.util.Optional;
import java.util.Set;

record TrialOutcome(TrialStatus status, HttpRequestResponse baseline, List<ProbeObservation> probes,
                    Optional<HttpRequestResponse> control, Set<HttpRequestResponse> sentOutsideBurp) {

    enum TrialStatus {
        CONCLUSIVE, BASELINE_NOT_SUCCESSFUL, BASELINE_UNREACHABLE_OUTSIDE_BURP, CONTROL_DIVERGED
    }

    TrialOutcome {
        probes = List.copyOf(probes);
    }

    TrialOutcome(TrialStatus status, HttpRequestResponse baseline, List<ProbeObservation> probes,
                 Optional<HttpRequestResponse> control) {
        this(status, baseline, probes, control, Set.of());
    }

    static TrialOutcome baselineNotSuccessful(HttpRequestResponse baseline) {
        return baselineFailed(TrialStatus.BASELINE_NOT_SUCCESSFUL, baseline);
    }

    static TrialOutcome baselineFailed(TrialStatus status, HttpRequestResponse baseline) {
        return new TrialOutcome(status, baseline, List.of(), Optional.empty());
    }

    boolean wentOutsideBurp(HttpRequestResponse exchange) {
        return sentOutsideBurp.contains(exchange);
    }

    boolean baselineUnansweredOutsideBurp() {
        return status == TrialStatus.BASELINE_UNREACHABLE_OUTSIDE_BURP;
    }

    boolean baselineAnsweredUnsuccessfully() {
        return status == TrialStatus.BASELINE_NOT_SUCCESSFUL && baseline != null && baseline.response() != null;
    }

    boolean conclusive() {
        return status == TrialStatus.CONCLUSIVE;
    }

    boolean everyProbeAnswered() {
        return probes.stream().noneMatch(probe -> probe.verdict() == ProbeVerdict.INCONCLUSIVE);
    }

    boolean fullyAnswered() {
        return conclusive() && everyProbeAnswered();
    }

    HostSettlement requestSettlement() {
        if (baselineUnansweredOutsideBurp()) {
            return HostSettlement.SETTLED;
        }
        if (status == TrialStatus.BASELINE_NOT_SUCCESSFUL) {
            return HostSettlement.NOT_PROBED;
        }
        return fullyAnswered() ? HostSettlement.SETTLED : HostSettlement.INCONCLUSIVE;
    }

    List<ProbeObservation> admittedIn(AdmissionCategory category) {
        return probes.stream().filter(probe -> probe.admittedIn(category)).toList();
    }
}
