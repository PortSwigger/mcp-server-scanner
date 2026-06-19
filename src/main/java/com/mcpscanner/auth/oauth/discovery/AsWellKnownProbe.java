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
import com.nimbusds.oauth2.sdk.as.AuthorizationServerMetadata;

import java.net.URI;
import java.net.URISyntaxException;
import java.util.Optional;

public class AsWellKnownProbe implements MetadataProbe {

    private static final String PURPOSE = "Authorization Server Metadata (.well-known)";
    private static final int HTTP_OK = 200;

    private final Http http;
    private final SuspiciousDestinationGate gate;
    private final McpEventLog eventLog;

    public AsWellKnownProbe(Http http) {
        this(http, defaultGate(null), null);
    }

    public AsWellKnownProbe(Http http, McpEventLog eventLog) {
        this(http, defaultGate(eventLog), eventLog);
    }

    public AsWellKnownProbe(Http http, SuspiciousDestinationGate gate, McpEventLog eventLog) {
        this.http = http;
        this.gate = gate;
        this.eventLog = eventLog != null ? eventLog : McpEventLog.noop();
    }

    @Override
    public Optional<DiscoveredMetadata> probe(URI mcpResource) {
        return wellKnownUrl(mcpResource)
                .flatMap(url -> gateUrl(url, mcpResource))
                .flatMap(url -> fetchBody(url).flatMap(body ->
                        MetadataParsers.parseAs(body, eventLog, url.toString())))
                .map(AsWellKnownProbe::toDiscoveredMetadata);
    }

    private Optional<URI> gateUrl(URI url, URI mcpEndpoint) {
        SuspiciousDestinationGate.Decision decision = gate.evaluate(
                url, FetchPurpose.of(PURPOSE, mcpEndpoint));
        if (decision.isDenied()) {
            warn("AS well-known fetch blocked by gate: " + url);
            return Optional.empty();
        }
        return Optional.of(url);
    }

    private static Optional<URI> wellKnownUrl(URI mcpResource) {
        try {
            return Optional.of(new URI(
                    mcpResource.getScheme(),
                    null,
                    mcpResource.getHost(),
                    mcpResource.getPort(),
                    OAuthWellKnownPaths.AS_WELL_KNOWN_PATH,
                    null,
                    null));
        } catch (URISyntaxException e) {
            return Optional.empty();
        }
    }

    private Optional<String> fetchBody(URI url) {
        HttpRequest request = HttpRequest.httpRequestFromUrl(url.toString());
        HttpRequestResponse rr = http.sendRequest(request, DiscoveryRequestOptions.noRedirect());
        HttpResponse response = rr.response();
        if (response == null || response.statusCode() != HTTP_OK) {
            warn("AS well-known fetch failed for " + url + ": "
                    + (response == null ? "no response" : "status " + response.statusCode()));
            return Optional.empty();
        }
        return Optional.ofNullable(response.bodyToString());
    }

    private void warn(String message) {
        eventLog.warn(message);
    }

    private static DiscoveredMetadata toDiscoveredMetadata(AuthorizationServerMetadata metadata) {
        return new DiscoveredMetadata(URI.create(metadata.getIssuer().getValue()), DiscoverySource.AS_WELL_KNOWN, metadata);
    }

    private static SuspiciousDestinationGate defaultGate(McpEventLog eventLog) {
        // AS well-known is same-origin with the MCP endpoint by construction,
        // so safe default = alwaysAllow (the gate will still hard-block on
        // invalid scheme / unresolvable host).
        return DefaultSuspiciousDestinationGate.withConfirmer(
                SuspiciousDestinationConfirmer.alwaysAllow(), eventLog);
    }
}
