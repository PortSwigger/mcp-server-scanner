package com.mcpscanner.auth.oauth.discovery;

import burp.api.montoya.http.Http;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import com.mcpscanner.auth.oauth.safety.DefaultSuspiciousDestinationGate;
import com.mcpscanner.auth.oauth.safety.FetchPurpose;
import com.mcpscanner.auth.oauth.safety.SuspiciousDestinationConfirmer;
import com.mcpscanner.auth.oauth.safety.SuspiciousDestinationGate;
import com.mcpscanner.logging.McpEventLog;

import java.net.URI;
import java.net.URISyntaxException;
import java.util.Optional;

public class PrmWellKnownProbe implements MetadataProbe {

    private static final String PURPOSE = "Protected Resource Metadata (.well-known)";
    private static final int HTTP_OK = 200;

    private final Http http;
    private final PrmToAsResolver resolver;
    private final SuspiciousDestinationGate gate;
    private final McpEventLog eventLog;

    public PrmWellKnownProbe(Http http, PrmToAsResolver resolver) {
        this(http, resolver, defaultGate(null), null);
    }

    public PrmWellKnownProbe(Http http, PrmToAsResolver resolver, McpEventLog eventLog) {
        this(http, resolver, defaultGate(eventLog), eventLog);
    }

    public PrmWellKnownProbe(Http http,
                             PrmToAsResolver resolver,
                             SuspiciousDestinationGate gate,
                             McpEventLog eventLog) {
        this.http = http;
        this.resolver = resolver;
        this.gate = gate;
        this.eventLog = eventLog != null ? eventLog : McpEventLog.noop();
    }

    @Override
    public Optional<DiscoveredMetadata> probe(URI mcpResource) {
        return wellKnownUrl(mcpResource)
                .flatMap(prmUrl -> gatePrmUrl(prmUrl, mcpResource))
                .filter(this::respondsWith200)
                .flatMap(prmUrl -> resolver.resolve(prmUrl, DiscoverySource.PRM_WELL_KNOWN, mcpResource));
    }

    private Optional<URI> gatePrmUrl(URI prmUrl, URI mcpEndpoint) {
        SuspiciousDestinationGate.Decision decision = gate.evaluate(
                prmUrl, FetchPurpose.of(PURPOSE, mcpEndpoint));
        if (decision.isDenied()) {
            warn("PRM well-known fetch blocked by gate: " + prmUrl);
            return Optional.empty();
        }
        return Optional.of(prmUrl);
    }

    private static Optional<URI> wellKnownUrl(URI mcpResource) {
        try {
            return Optional.of(new URI(
                    mcpResource.getScheme(),
                    null,
                    mcpResource.getHost(),
                    mcpResource.getPort(),
                    OAuthWellKnownPaths.PRM_WELL_KNOWN_PATH,
                    null,
                    null));
        } catch (URISyntaxException e) {
            return Optional.empty();
        }
    }

    private boolean respondsWith200(URI prmUrl) {
        HttpRequest request = HttpRequest.httpRequestFromUrl(prmUrl.toString());
        HttpRequestResponse rr = http.sendRequest(request, DiscoveryRequestOptions.noRedirect());
        HttpResponse response = rr.response();
        if (response == null) {
            warn("PRM well-known fetch failed for " + prmUrl + ": no response");
            return false;
        }
        return response.statusCode() == HTTP_OK;
    }

    private void warn(String message) {
        eventLog.warn(message);
    }

    private static SuspiciousDestinationGate defaultGate(McpEventLog eventLog) {
        // PRM well-known is same-origin with the MCP endpoint by construction,
        // so safe default = alwaysAllow (the gate will still hard-block on
        // invalid scheme / unresolvable host).
        return DefaultSuspiciousDestinationGate.withConfirmer(
                SuspiciousDestinationConfirmer.alwaysAllow(), eventLog);
    }
}
