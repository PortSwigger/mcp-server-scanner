package com.mcpscanner.auth.oauth.discovery;

import burp.api.montoya.http.Http;
import burp.api.montoya.http.message.responses.HttpResponse;
import com.mcpscanner.auth.oauth.safety.DefaultSuspiciousDestinationGate;
import com.mcpscanner.auth.oauth.safety.FetchPurpose;
import com.mcpscanner.auth.oauth.safety.SuspiciousDestinationGate;
import com.mcpscanner.logging.McpEventLog;

import java.net.URI;
import java.util.Optional;
import java.util.List;

public class WwwAuthenticateProbe implements MetadataProbe {

    private static final String WWW_AUTHENTICATE_HEADER = "WWW-Authenticate";
    private static final String PURPOSE = "WWW-Authenticate resource_metadata";

    private final AuthChallengeRequest challengeRequest;
    private final PrmToAsResolver resolver;
    private final SuspiciousDestinationGate gate;
    private final McpEventLog eventLog;
    private final DiscoveryTrail trail;

    public WwwAuthenticateProbe(Http http,
                                PrmToAsResolver resolver,
                                SuspiciousDestinationGate gate,
                                McpEventLog eventLog) {
        this(http, resolver, gate, eventLog, new DiscoveryTrail());
    }

    WwwAuthenticateProbe(Http http,
                         PrmToAsResolver resolver,
                         SuspiciousDestinationGate gate,
                         McpEventLog eventLog,
                         DiscoveryTrail trail) {
        this.trail = trail;
        this.challengeRequest = new AuthChallengeRequest(http, eventLog);
        this.resolver = resolver;
        this.gate = gate;
        this.eventLog = eventLog != null ? eventLog : McpEventLog.noop();
    }

    @Override
    public Optional<DiscoveredMetadata> probe(URI mcpResource) {
        return sendChallengeRequest(mcpResource).flatMap(response -> resolveMetadata(response, mcpResource));
    }

    private Optional<DiscoveredMetadata> resolveMetadata(HttpResponse response, URI mcpResource) {
        Optional<List<String>> challengedScopes = MetadataParsers.parseScopesFromWwwAuthenticate(
                response.headerValue(WWW_AUTHENTICATE_HEADER));
        Optional<URI> advertisedUrl = extractResourceMetadataUrl(response);
        DiscoverySource source = advertisedUrl.isPresent()
                ? DiscoverySource.WWW_AUTHENTICATE_HEADER : DiscoverySource.PRM_WELL_KNOWN;
        Optional<URI> prmUrl = advertisedUrl.or(() -> challengedScopes.isPresent()
                ? OAuthWellKnownPaths.protectedResourceMetadataUrl(mcpResource) : Optional.empty());
        return prmUrl.flatMap(candidate -> gateUrl(candidate, mcpResource))
                .flatMap(url -> resolver.resolve(url, source, mcpResource))
                .map(metadata -> challengedScopes.map(metadata::withScopes).orElse(metadata))
                .map(metadata -> metadata.withWwwAuthenticateChallenge(
                        response.headerValue(WWW_AUTHENTICATE_HEADER)));
    }

    private Optional<HttpResponse> sendChallengeRequest(URI mcpResource) {
        ChallengeReply reply = challengeRequest.send(mcpResource);
        Optional<HttpResponse> response = reply.answer();
        if (reply instanceof ChallengeReply.Streamed) {
            trail.challengeFailed("the server streamed its reply, so it sent no WWW-Authenticate challenge");
        } else if (response.isEmpty()) {
            warn("WWW-Authenticate challenge probe failed for " + mcpResource + ": no response");
            trail.challengeFailed("no response");
        }
        response.ifPresent(this::recordChallenge);
        return response;
    }

    private void recordChallenge(HttpResponse response) {
        String challenge = response.headerValue(WWW_AUTHENTICATE_HEADER);
        if (challenge == null) {
            trail.challengeFailed("status " + response.statusCode() + " response had no WWW-Authenticate header");
        } else {
            trail.challengeReceived(challenge);
        }
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

}
