package com.mcpscanner.checks.catalog.originhostadmission;

import burp.api.montoya.http.Http;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import com.mcpscanner.checks.api.CheckLog;
import com.mcpscanner.checks.api.HostSettlement;
import com.mcpscanner.checks.api.SkipReason;
import com.mcpscanner.checks.shared.auth.CredentialHeaders;
import com.mcpscanner.checks.shared.session.OutsideBurpExchanges;
import com.mcpscanner.checks.shared.session.StreamingFallback;

import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

final class PreflightCorsRead {

    private static final String SCOPE = "The scanner sent the CORS preflight a browser sends before this JSON "
            + "request, then replayed the captured read-only MCP request with only the Origin header changed. "
            + "The server approved the preflight, returned the same successful result as a fresh baseline and a "
            + "final control, and allowed the foreign origin to read that reply. The scanner did not drive a "
            + "browser or establish that the operation is sensitive.";

    private final CheckLog log;
    private final CorsProbe probe;
    private final AdmissionRoute route;
    private final CapturedSessionReplay replay;
    private final StreamingFallback streamedReplies;

    PreflightCorsRead(CheckLog log, CredentialHeaders credentials, StreamingFallback streamedReplies,
                      CapturedSessionReplay replay) {
        this.log = log;
        this.probe = new CorsProbe(credentials);
        this.route = new AdmissionRoute("direct", ProbeDelivery.direct(credentials),
                new AdmissionTrial(List.of(CorsProbe.FOREIGN_ORIGIN_POST), streamedReplies));
        this.replay = replay;
        this.streamedReplies = streamedReplies;
    }

    CorsReading read(HttpRequestResponse hostBase, Http http, String test) {
        HttpRequest delivered = route.deliver(hostBase.request());
        OutsideBurpExchanges outsideBurp = new OutsideBurpExchanges(http);
        HttpRequestResponse preflight = streamedReplies.around(outsideBurp).sendRequest(probe.preflightFor(delivered));
        CorsEvidence preflightEvidence = new CorsEvidence("the preflight", preflight,
                outsideBurp.sent().contains(preflight));
        CorsGrant grant = CorsGrant.of(preflight);
        if (!grant.answered() || grant.serverError()) {
            log.notRun(test, SkipReason.transportFailure("the CORS preflight got no usable response ("
                    + grant.status() + ")"));
            return CorsReading.nothingFound(HostSettlement.INCONCLUSIVE);
        }
        if (!grant.approvesPreflight(CorsProbe.FOREIGN_ORIGIN, probe.requestedHeaders(delivered))) {
            return decided("the preflight did not approve the foreign origin (" + grant.status() + ", "
                    + grant.describe() + ")");
        }
        return replayed(preflightEvidence, grant, replay.retryingInFreshSession(route, hostBase, http), test);
    }

    private CorsReading replayed(CorsEvidence preflight, CorsGrant preflightGrant, DeliveredTrial trial,
                                 String test) {
        TrialOutcome outcome = trial.outcome();
        Optional<SkipReason> unprobed = outcome.baselineUnansweredOutsideBurp()
                ? Optional.of(SkipReason.streamedReply(AdmissionDecisions.UNREACHABLE_STREAMED_BASELINE))
                : UnprobedTrials.requestTrial(outcome);
        if (unprobed.isPresent()) {
            log.notRun(test, unprobed.get());
            return CorsReading.nothingFound(outcome.requestSettlement());
        }
        List<ProbeObservation> admitted = outcome.admittedIn(AdmissionCategory.ORIGIN);
        if (!outcome.conclusive() || admitted.isEmpty()) {
            logDecision("the replay under the foreign origin was not admitted: " + outcome.status() + " "
                    + outcome.probes().stream().map(ProbeObservation::summary).toList());
            return CorsReading.nothingFound(outcome.requestSettlement());
        }
        CorsGrant replyGrant = CorsGrant.of(admitted.get(0).exchange());
        if (!replyGrant.approves(CorsProbe.FOREIGN_ORIGIN)) {
            return decided("the admitted reply does not let the foreign origin read it (" + replyGrant.describe()
                    + ")");
        }
        logDecision("CORS lets " + CorsProbe.FOREIGN_ORIGIN + " read the reply via " + trial.label());
        return CorsReading.found(new CorsFinding(SCOPE, probe.authOf(trial.delivered()),
                preflightGrant.approvesWithCredentials(CorsProbe.FOREIGN_ORIGIN)
                        && replyGrant.approvesWithCredentials(CorsProbe.FOREIGN_ORIGIN),
                evidence(preflight, outcome, admitted.get(0))));
    }

    private CorsReading decided(String decision) {
        logDecision(decision);
        return CorsReading.nothingFound(HostSettlement.SETTLED);
    }

    private void logDecision(String decision) {
        log.info("decision: " + decision);
    }

    private static List<CorsEvidence> evidence(CorsEvidence preflight, TrialOutcome outcome,
                                               ProbeObservation admitted) {
        List<CorsEvidence> evidence = new ArrayList<>();
        evidence.add(preflight);
        evidence.add(new CorsEvidence("the baseline request", outcome.baseline(),
                outcome.wentOutsideBurp(outcome.baseline())));
        evidence.add(new CorsEvidence("the " + admitted.probe().label() + " request", admitted.exchange(),
                outcome.wentOutsideBurp(admitted.exchange())));
        outcome.control().ifPresent(control -> evidence.add(
                new CorsEvidence("the control request", control, outcome.wentOutsideBurp(control))));
        return evidence;
    }
}
