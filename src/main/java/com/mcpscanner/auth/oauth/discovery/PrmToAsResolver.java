package com.mcpscanner.auth.oauth.discovery;

import burp.api.montoya.http.Http;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import com.fasterxml.jackson.databind.JsonNode;
import com.mcpscanner.auth.oauth.OAuthMetadataConsistencyListener;
import com.mcpscanner.auth.oauth.safety.FetchPurpose;
import com.mcpscanner.auth.oauth.safety.SuspiciousDestinationConfirmer;
import com.mcpscanner.auth.oauth.safety.SuspiciousDestinationGate;
import com.mcpscanner.auth.oauth.safety.DefaultSuspiciousDestinationGate;
import com.mcpscanner.logging.McpEventLog;
import com.nimbusds.oauth2.sdk.as.AuthorizationServerMetadata;

import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.util.Optional;

public class PrmToAsResolver {

    private static final String AUTHORIZATION_SERVERS_FIELD = "authorization_servers";
    private static final String PURPOSE_PRM_DOC = "Protected Resource Metadata";
    private static final String PURPOSE_AS_DOC = "Authorization Server Metadata";

    private final Http http;
    private final McpEventLog eventLog;
    private final SuspiciousDestinationGate gate;
    private final OAuthMetadataConsistencyListener consistencyListener;

    public PrmToAsResolver(Http http) {
        this(http, null, defaultGate(null), OAuthMetadataConsistencyListener.noop());
    }

    public PrmToAsResolver(Http http, McpEventLog eventLog) {
        this(http, eventLog, defaultGate(eventLog), OAuthMetadataConsistencyListener.noop());
    }

    public PrmToAsResolver(Http http, McpEventLog eventLog, SuspiciousDestinationGate gate) {
        this(http, eventLog, gate, OAuthMetadataConsistencyListener.noop());
    }

    public PrmToAsResolver(Http http,
                           McpEventLog eventLog,
                           SuspiciousDestinationGate gate,
                           OAuthMetadataConsistencyListener consistencyListener) {
        this.http = http;
        this.eventLog = eventLog != null ? eventLog : McpEventLog.noop();
        this.gate = gate;
        this.consistencyListener = consistencyListener != null
                ? consistencyListener : OAuthMetadataConsistencyListener.noop();
    }

    public Optional<DiscoveredMetadata> resolve(URI prmDocUrl, DiscoverySource source) {
        return resolve(prmDocUrl, source, null);
    }

    public Optional<DiscoveredMetadata> resolve(URI prmDocUrl, DiscoverySource source, URI mcpEndpoint) {
        SuspiciousDestinationGate.Decision prmDecision = gate.evaluate(
                prmDocUrl, FetchPurpose.of(PURPOSE_PRM_DOC, mcpEndpoint));
        if (prmDecision.isDenied()) {
            warn("PRM fetch blocked by gate: " + prmDocUrl);
            return Optional.empty();
        }

        Optional<String> rawPrmBody = fetchBody(prmDocUrl);
        if (rawPrmBody.isEmpty()) {
            return Optional.empty();
        }
        String prmBodyText = rawPrmBody.get();
        Optional<JsonNode> prmJson = MetadataParsers.parseJsonObject(prmBodyText, eventLog, prmDocUrl.toString());
        if (prmJson.isEmpty()) {
            return Optional.empty();
        }
        Optional<URI> asIssuerOpt = extractAuthorizationServer(prmJson.get());
        if (asIssuerOpt.isEmpty()) {
            return Optional.empty();
        }

        URI asIssuer = asIssuerOpt.get();
        checkPrmAuthorizationServerHost(prmDocUrl, asIssuer, prmBodyText, mcpEndpoint);

        return fetchAsMetadata(asIssuer, prmDocUrl, mcpEndpoint)
                .map(asMetadata -> new DiscoveredMetadata(asIssuer, source, asMetadata));
    }

    private void checkPrmAuthorizationServerHost(URI prmDocUrl,
                                                  URI asIssuer,
                                                  String rawPrmBody,
                                                  URI mcpEndpoint) {
        String mcpHost = mcpEndpoint != null ? mcpEndpoint.getHost() : prmDocUrl.getHost();
        if (mcpHost == null) {
            return;
        }
        String asHost = asIssuer.getHost();
        if (asHost == null || asHost.equalsIgnoreCase(mcpHost)) {
            return;
        }
        warn("PRM authorization_servers host mismatch: MCP endpoint host=" + mcpHost
                + ", AS issuer host=" + asHost + ". Proceeding permissively.");
        byte[] rawBytes = rawPrmBody.getBytes(StandardCharsets.UTF_8);
        try {
            consistencyListener.onPrmAuthorizationServerHostMismatch(
                    prmDocUrl, mcpHost, asIssuer.toString(), rawBytes);
        } catch (RuntimeException listenerFailure) {
            warn("OAuthMetadataConsistencyListener.onPrmAuthorizationServerHostMismatch threw "
                    + listenerFailure.getClass().getSimpleName()
                    + ": " + listenerFailure.getMessage()
                    + " (continuing with PRM resolution)");
        }
    }

    private Optional<String> fetchBody(URI uri) {
        HttpRequest request = HttpRequest.httpRequestFromUrl(uri.toString());
        HttpRequestResponse rr = http.sendRequest(request, DiscoveryRequestOptions.noRedirect());
        HttpResponse response = rr.response();
        if (response == null) {
            warn("PRM/AS document fetch failed for " + uri + ": no response");
            return Optional.empty();
        }
        if (response.statusCode() / 100 != 2) {
            return Optional.empty();
        }
        return Optional.ofNullable(response.bodyToString());
    }

    private Optional<URI> extractAuthorizationServer(JsonNode prmDoc) {
        JsonNode servers = prmDoc.get(AUTHORIZATION_SERVERS_FIELD);
        if (servers == null || !servers.isArray() || servers.isEmpty()) {
            warn("PRM document missing 'authorization_servers' array");
            return Optional.empty();
        }
        try {
            return Optional.of(URI.create(servers.get(0).asText()));
        } catch (IllegalArgumentException e) {
            warn("PRM 'authorization_servers' contains invalid URI: " + e.getMessage());
            return Optional.empty();
        }
    }

    private Optional<AuthorizationServerMetadata> fetchAsMetadata(URI issuer, URI sourceUrl, URI mcpEndpoint) {
        URI asUrl = asMetadataUrl(issuer);
        SuspiciousDestinationGate.Decision decision = gate.evaluate(
                asUrl, FetchPurpose.of(PURPOSE_AS_DOC, mcpEndpoint, sourceUrl));
        if (decision.isDenied()) {
            warn("AS metadata fetch blocked by gate: " + asUrl);
            return Optional.empty();
        }
        return fetchBody(asUrl).flatMap(body -> MetadataParsers.parseAs(body, eventLog, asUrl.toString()));
    }

    private void warn(String message) {
        eventLog.warn(message);
    }

    private static URI asMetadataUrl(URI issuer) {
        String issuerString = issuer.toString();
        String trimmed = issuerString.endsWith("/")
                ? issuerString.substring(0, issuerString.length() - 1)
                : issuerString;
        return URI.create(trimmed + OAuthWellKnownPaths.AS_WELL_KNOWN_PATH);
    }

    private static SuspiciousDestinationGate defaultGate(McpEventLog eventLog) {
        // Safe default: hostile classifications are denied unless callers
        // inject a confirmer that can ask the user.
        return DefaultSuspiciousDestinationGate.withConfirmer(
                SuspiciousDestinationConfirmer.alwaysDeny(), eventLog);
    }
}
