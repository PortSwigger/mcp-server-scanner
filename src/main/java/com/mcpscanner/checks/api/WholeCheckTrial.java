package com.mcpscanner.checks.api;

import burp.api.montoya.http.Http;
import burp.api.montoya.http.message.HttpRequestResponse;

import java.util.Optional;

public record WholeCheckTrial(HostCheck check) implements HostTrial {

    @Override
    public Optional<SkipReason> whyNotApplicable(HttpRequestResponse hostBaseRequestResponse) {
        return check.appliesTo(hostBaseRequestResponse)
                ? Optional.empty()
                : Optional.of(SkipReason.notApplicable("applies only to " + check.appliesOnlyTo()));
    }

    @Override
    public HostTrialResult run(HttpRequestResponse hostBaseRequestResponse, Http http) {
        return HostTrialResult.settled(check.audit(hostBaseRequestResponse, http));
    }
}
