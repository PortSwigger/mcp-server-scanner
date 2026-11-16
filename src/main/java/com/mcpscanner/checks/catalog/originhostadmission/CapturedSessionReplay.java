package com.mcpscanner.checks.catalog.originhostadmission;

import burp.api.montoya.http.Http;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;

final class CapturedSessionReplay {

    private static final String FRESH_SESSION_LABEL = ", in a fresh session (the captured session was not usable)";

    private final FreshProbeSession freshSession;

    CapturedSessionReplay(FreshProbeSession freshSession) {
        this.freshSession = freshSession;
    }

    DeliveredTrial once(AdmissionRoute route, HttpRequestResponse hostBase, Http http) {
        return attempt(route, route.label(), route.deliver(hostBase.request()), http);
    }

    DeliveredTrial retryingInFreshSession(AdmissionRoute route, HttpRequestResponse hostBase, Http http) {
        DeliveredTrial trial = once(route, hostBase, http);
        if (!trial.refusedInCapturedSession()) {
            return trial;
        }
        return freshSession.within(hostBase, trial.delivered(), http,
                        fresh -> attempt(route, route.label() + FRESH_SESSION_LABEL, fresh, http))
                .orElse(trial);
    }

    private static DeliveredTrial attempt(AdmissionRoute route, String label, HttpRequest delivered, Http http) {
        return new DeliveredTrial(label, delivered, route.run(delivered, http));
    }
}
