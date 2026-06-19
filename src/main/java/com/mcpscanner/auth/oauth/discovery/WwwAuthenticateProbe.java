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
import java.util.Optional;

public class WwwAuthenticateProbe implements MetadataProbe {

    private static final String WWW_AUTHENTICATE_HEADER = "WWW-Authenticate";
    private static final String PURPOSE = "WWW-Authenticate resource_metadata";

    private final Http http;
    private final PrmToAsResolver resolver;
    private final SuspiciousDestinationGate gate;
    private final McpEventLog eventLog;

    public WwwAuthenticateProbe(Http http, PrmToAsResolver resolver) {
        this(http, resolver, defaultGate(null), null);
    }

    public WwwAuthenticateProbe(Http http, PrmToAsResolver resolver, McpEventLog eventLog) {
        this(http, resolver, defaultGate(eventLog), eventLog);
    }

    public WwwAuthenticateProbe(Http http,
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
        return sendChallengeRequest(mcpResource)
                .flatMap(WwwAuthenticateProbe::extractResourceMetadataUrl)
                .flatMap(candidate -> gateUrl(candidate, mcpResource))
                .flatMap(prmUrl -> resolver.resolve(prmUrl, DiscoverySource.WWW_AUTHENTICATE_HEADER, mcpResource));
    }

    private Optional<HttpResponse> sendChallengeRequest(URI mcpResource) {
        HttpRequest request = HttpRequest.httpRequestFromUrl(mcpResource.toString())
                .withMethod("POST")
                .withAddedHeader("Content-Type", "application/json")
                .withBody("{}");
        HttpRequestResponse rr = http.sendRequest(request, DiscoveryRequestOptions.noRedirect());
        HttpResponse response = rr.response();
        if (response == null) {
            warn("WWW-Authenticate challenge probe failed for " + mcpResource + ": no response");
            return Optional.empty();
        }
        return Optional.of(response);
    }

    private Optional<URI> gateUrl(URI candidate, URI mcpEndpoint) {
        SuspiciousDestinationGate.Decision decision = gate.evaluate(
                candidate, FetchPurpose.of(PURPOSE, mcpEndpoint));
        if (decision.isDenied()) {
            warn("WWW-Authenticate resource_metadata URL rejected: " + candidate);
            return Optional.empty();
        }
        return Optional.of(candidate);
    }

    private void warn(String message) {
        eventLog.warn(message);
    }

    private static Optional<URI> extractResourceMetadataUrl(HttpResponse response) {
        return Optional.ofNullable(response.headerValue(WWW_AUTHENTICATE_HEADER))
                .flatMap(MetadataParsers::parseResourceMetadataFromWwwAuthenticate);
    }

    private static SuspiciousDestinationGate defaultGate(McpEventLog eventLog) {
        // Safe default: hostile classifications are denied unless callers
        // inject a confirmer that can ask the user.
        return DefaultSuspiciousDestinationGate.withConfirmer(
                SuspiciousDestinationConfirmer.alwaysDeny(), eventLog);
    }
}
