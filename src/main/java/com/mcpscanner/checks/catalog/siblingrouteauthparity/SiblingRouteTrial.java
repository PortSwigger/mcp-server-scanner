package com.mcpscanner.checks.catalog.siblingrouteauthparity;

import burp.api.montoya.http.Http;
import burp.api.montoya.http.message.HttpRequestResponse;
import com.mcpscanner.checks.api.HostTrial;
import com.mcpscanner.checks.api.HostTrialResult;
import com.mcpscanner.checks.api.SkipReason;

import java.util.Optional;

final class SiblingRouteTrial implements HostTrial {

    private final SiblingRouteAuthParityCheck check;

    SiblingRouteTrial(SiblingRouteAuthParityCheck check) {
        this.check = check;
    }

    @Override
    public Optional<SkipReason> whyNotApplicable(HttpRequestResponse hostBaseRequestResponse) {
        return check.appliesTo(hostBaseRequestResponse)
                ? Optional.empty()
                : Optional.of(SkipReason.notApplicable("applies only to " + check.appliesOnlyTo()));
    }

    @Override
    public HostTrialResult run(HttpRequestResponse hostBaseRequestResponse, Http http) {
        AuditOutcome outcome = check.outcomeOf(hostBaseRequestResponse, http);
        return new HostTrialResult(check.render(outcome), outcome.settlement());
    }
}
