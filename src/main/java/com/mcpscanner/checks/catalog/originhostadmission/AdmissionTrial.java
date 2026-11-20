package com.mcpscanner.checks.catalog.originhostadmission;

import burp.api.montoya.http.Http;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import com.fasterxml.jackson.databind.JsonNode;
import com.mcpscanner.checks.shared.auth.oracle.ReplyResults;
import com.mcpscanner.checks.shared.auth.oracle.ResultEquivalence;
import com.mcpscanner.checks.shared.auth.oracle.SameResultValue;
import com.mcpscanner.checks.shared.session.OutsideBurpExchanges;
import com.mcpscanner.checks.shared.session.StreamingFallback;

import com.mcpscanner.mcp.TooManyRequests;
import java.util.List;
import java.util.Optional;
import java.util.Set;

final class AdmissionTrial {

    private static final Set<Integer> TRANSIENT_STATUSES = Set.of(408, 425, TooManyRequests.STATUS);

    private final ReplyResults replies = new ReplyResults();
    private final ResultEquivalence sameResult = new SameResultValue();
    private final List<AdmissionProbe> probes;
    private final StreamingFallback streamedReplies;

    AdmissionTrial(List<AdmissionProbe> probes, StreamingFallback streamedReplies) {
        this.probes = List.copyOf(probes);
        this.streamedReplies = streamedReplies;
    }

    TrialOutcome run(HttpRequest deliveredSeed, Http burp) {
        OutsideBurpExchanges outsideBurp = new OutsideBurpExchanges(burp);
        Http http = streamedReplies.around(outsideBurp);
        HttpRequestResponse baseline = http.sendRequest(deliveredSeed);
        Optional<JsonNode> expected = replies.successfulResult(baseline);
        if (expected.isEmpty()) {
            return TrialOutcome.baselineFailed(unsuccessfulBaseline(baseline, deliveredSeed), baseline);
        }
        List<ProbeObservation> observations = probes.stream()
                .map(probe -> observe(probe, http.sendRequest(probe.applyTo(deliveredSeed)), expected.get()))
                .toList();
        HttpRequestResponse control = http.sendRequest(deliveredSeed);
        TrialOutcome.TrialStatus status = matches(control, expected.get())
                ? TrialOutcome.TrialStatus.CONCLUSIVE : TrialOutcome.TrialStatus.CONTROL_DIVERGED;
        return new TrialOutcome(status, baseline, observations, outsideBurp.sent());
    }

    private TrialOutcome.TrialStatus unsuccessfulBaseline(HttpRequestResponse baseline, HttpRequest deliveredSeed) {
        if (answered(baseline) || !streamedReplies.sendsOutsideBurp(deliveredSeed)) {
            return TrialOutcome.TrialStatus.BASELINE_NOT_SUCCESSFUL;
        }
        return TrialOutcome.TrialStatus.BASELINE_UNREACHABLE_OUTSIDE_BURP;
    }

    private static boolean answered(HttpRequestResponse exchange) {
        return exchange != null && exchange.response() != null;
    }

    private ProbeObservation observe(AdmissionProbe probe, HttpRequestResponse exchange, JsonNode expected) {
        return new ProbeObservation(probe, exchange, verdictOf(exchange, expected));
    }

    private ProbeVerdict verdictOf(HttpRequestResponse exchange, JsonNode expected) {
        Optional<JsonNode> result = replies.successfulResult(exchange);
        if (result.isPresent()) {
            return sameResult.equivalent(expected, result.get())
                    ? ProbeVerdict.ADMITTED : ProbeVerdict.ADMITTED_WITH_ANOTHER_RESULT;
        }
        return replies.refused(exchange) || clientRejection(exchange)
                ? ProbeVerdict.REFUSED : ProbeVerdict.INCONCLUSIVE;
    }

    private static boolean clientRejection(HttpRequestResponse exchange) {
        if (exchange == null || exchange.response() == null) {
            return false;
        }
        int status = exchange.response().statusCode();
        return status >= 400 && status < 500 && !TRANSIENT_STATUSES.contains(status);
    }

    private boolean matches(HttpRequestResponse exchange, JsonNode expected) {
        return replies.successfulResult(exchange).filter(result -> sameResult.equivalent(expected, result)).isPresent();
    }
}
