package com.mcpscanner.checks.catalog.originhostadmission;

import burp.api.montoya.http.Http;
import burp.api.montoya.http.HttpService;
import burp.api.montoya.http.message.HttpRequestResponse;
import com.mcpscanner.checks.api.HostSettlement;
import com.mcpscanner.checks.api.HostTrial;
import com.mcpscanner.checks.api.HostTrialResult;
import com.mcpscanner.checks.api.SkipReason;
import com.mcpscanner.checks.api.SkipSubject;
import com.mcpscanner.checks.shared.auth.CredentialHeaders;
import com.mcpscanner.checks.shared.session.StreamingFallback;

import java.util.Optional;
import java.util.function.Supplier;

final class RequestAdmissionHostTrial implements HostTrial {

    private final AdmissionDecisions decisions;
    private final Supplier<Optional<HttpService>> streamProxy;
    private final AdmissionRoute direct;
    private final AdmissionRoute ownSseStream;
    private final CapturedSessionReplay replay;
    private final ReplaySafeRequests replaySafe = new ReplaySafeRequests();

    RequestAdmissionHostTrial(AdmissionDecisions decisions, CredentialHeaders credentials,
                              StreamingFallback streamedReplies, Supplier<Optional<HttpService>> streamProxy,
                              CapturedSessionReplay replay) {
        this.decisions = decisions;
        this.streamProxy = streamProxy;
        this.direct = AdmissionRoute.direct(credentials, streamedReplies);
        this.ownSseStream = AdmissionRoute.ownSseStream(credentials, streamedReplies);
        this.replay = replay;
    }

    @Override
    public Optional<SkipReason> whyNotApplicable(HttpRequestResponse hostBaseRequestResponse) {
        return replaySafe.whyRefused(hostBaseRequestResponse.request());
    }

    @Override
    public String subject(HttpRequestResponse hostBaseRequestResponse) {
        return "the Origin/Host request test on " + SkipSubject.of(hostBaseRequestResponse);
    }

    @Override
    public HostSettlement settlementOnFailure() {
        return HostSettlement.SETTLED;
    }

    @Override
    public HostTrialResult run(HttpRequestResponse hostBaseRequestResponse, Http http) {
        String test = subject(hostBaseRequestResponse);
        DeliveredTrial trial = streamProxy.get().isPresent()
                ? replay.once(ownSseStream, hostBaseRequestResponse, http)
                : replay.retryingInFreshSession(direct, hostBaseRequestResponse, http);
        TrialOutcome outcome = trial.outcome();
        return new HostTrialResult(decisions.decide(test, outcome, UnprobedTrials.requestTrial(outcome),
                trial.label(), trial.delivered()), outcome.requestSettlement());
    }
}
