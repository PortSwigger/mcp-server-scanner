package com.mcpscanner.checks;

import burp.api.montoya.http.Http;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import com.mcpscanner.mcp.HeaderMutation;

import java.util.ArrayList;
import java.util.List;
import java.util.function.Predicate;

public final class AuthProbeRunner {

    public record ProbeResult(AuthProbe probe, HttpRequestResponse response) {}

    private final Http http;
    private final Predicate<HttpRequestResponse> successOracle;

    public AuthProbeRunner(Http http, Predicate<HttpRequestResponse> successOracle) {
        this.http = http;
        this.successOracle = successOracle;
    }

    public List<ProbeResult> runAll(HttpRequest baseline, List<AuthProbe> probes) {
        List<ProbeResult> successes = new ArrayList<>();
        for (AuthProbe probe : probes) {
            HttpRequest mutated = HeaderMutation.apply(baseline, probe.headersToRemove(), probe.headersToOverride());
            HttpRequestResponse response = http.sendRequest(mutated);
            if (successOracle.test(response)) {
                successes.add(new ProbeResult(probe, response));
            }
        }
        return successes;
    }
}
