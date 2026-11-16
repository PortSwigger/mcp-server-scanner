package com.mcpscanner.checks.catalog.originhostadmission;

import burp.api.montoya.http.Http;
import burp.api.montoya.http.HttpService;
import burp.api.montoya.http.message.HttpRequestResponse;
import com.mcpscanner.checks.api.HostSettlement;
import com.mcpscanner.checks.api.HostTrial;
import com.mcpscanner.checks.api.HostTrialResult;
import com.mcpscanner.checks.api.SkipReason;
import com.mcpscanner.checks.api.SkipSubject;

import java.util.Optional;
import java.util.function.Supplier;

final class CorsPreflightHostTrial implements HostTrial {

    private final Supplier<Optional<HttpService>> streamProxy;
    private final PreflightCorsRead preflight;
    private final StreamCorsRead stream;
    private final CorsIssues issues = new CorsIssues(OriginHostAdmissionDescriptor.DESCRIPTOR);
    private final ReplaySafeRequests replaySafe = new ReplaySafeRequests();

    CorsPreflightHostTrial(Supplier<Optional<HttpService>> streamProxy, PreflightCorsRead preflight,
                           StreamCorsRead stream) {
        this.streamProxy = streamProxy;
        this.preflight = preflight;
        this.stream = stream;
    }

    @Override
    public Optional<SkipReason> whyNotApplicable(HttpRequestResponse hostBaseRequestResponse) {
        return replaySafe.whyRefused(hostBaseRequestResponse.request());
    }

    @Override
    public String subject(HttpRequestResponse hostBaseRequestResponse) {
        return "the CORS cross-origin read test on " + SkipSubject.of(hostBaseRequestResponse);
    }

    @Override
    public HostSettlement settlementOnFailure() {
        return HostSettlement.SETTLED;
    }

    @Override
    public HostTrialResult run(HttpRequestResponse hostBaseRequestResponse, Http http) {
        String test = subject(hostBaseRequestResponse);
        CorsReading reading = streamProxy.get().isPresent()
                ? stream.read(http, test)
                : preflight.read(hostBaseRequestResponse, http, test);
        return new HostTrialResult(reading.finding().map(issues::issueFor).stream().toList(),
                reading.settlement());
    }
}
