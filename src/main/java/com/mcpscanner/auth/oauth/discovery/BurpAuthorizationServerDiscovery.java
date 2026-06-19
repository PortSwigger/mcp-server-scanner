package com.mcpscanner.auth.oauth.discovery;

import burp.api.montoya.http.Http;
import burp.api.montoya.http.HttpService;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import com.fasterxml.jackson.databind.JsonNode;
import com.mcpscanner.auth.AuthHeaderNames;
import com.mcpscanner.auth.AuthStrategy;
import com.mcpscanner.auth.NoAuthStrategy;
import com.mcpscanner.logging.McpEventLog;
import com.mcpscanner.mcp.HeaderMutation;
import com.mcpscanner.mcp.ScannerSentinels;
import com.nimbusds.oauth2.sdk.as.AuthorizationServerMetadata;

import java.net.URI;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import java.util.function.Supplier;

public final class BurpAuthorizationServerDiscovery {

    private static final String WWW_AUTHENTICATE_HEADER = "WWW-Authenticate";
    private static final int HTTP_OK = 200;

    public record Result(Optional<AuthorizationServerMetadata> metadata,
                         List<HttpRequestResponse> probeResponses) {}

    private final McpEventLog eventLog;
    private final Supplier<AuthStrategy> authStrategySupplier;

    public BurpAuthorizationServerDiscovery() {
        this(McpEventLog.noop(), NoAuthStrategy::new);
    }

    public BurpAuthorizationServerDiscovery(McpEventLog eventLog) {
        this(eventLog, NoAuthStrategy::new);
    }

    public BurpAuthorizationServerDiscovery(McpEventLog eventLog, Supplier<AuthStrategy> authStrategySupplier) {
        this.eventLog = eventLog != null ? eventLog : McpEventLog.noop();
        this.authStrategySupplier = authStrategySupplier != null ? authStrategySupplier : NoAuthStrategy::new;
    }

    public Result discover(Http http, HttpRequestResponse baseRequestResponse) {
        List<HttpRequestResponse> probeResponses = new ArrayList<>();
        Optional<AuthorizationServerMetadata> viaWwwAuthenticate =
                discoverViaWwwAuthenticate(http, baseRequestResponse, probeResponses);
        if (viaWwwAuthenticate.isPresent()) {
            return new Result(viaWwwAuthenticate, probeResponses);
        }
        Optional<AuthorizationServerMetadata> viaFallback =
                discoverViaWellKnownFallback(http, baseRequestResponse.request().httpService(), probeResponses);
        if (viaFallback.isEmpty()) {
            warn("Burp-side AS discovery failed (no AS metadata via WWW-Authenticate or .well-known)");
        }
        return new Result(viaFallback, probeResponses);
    }

    private void warn(String message) {
        eventLog.warn(message);
    }

    private Optional<AuthorizationServerMetadata> discoverViaWwwAuthenticate(Http http,
                                                                             HttpRequestResponse baseRequestResponse,
                                                                             List<HttpRequestResponse> probeResponses) {
        Set<String> headersToStrip = AuthHeaderNames.authBearingHeaderNames(authStrategySupplier.get());
        HttpRequest stripped = HeaderMutation.apply(baseRequestResponse.request(),
                headersToStrip, ScannerSentinels.stripAuthOnly());
        HttpRequestResponse unauthenticated = http.sendRequest(stripped);
        probeResponses.add(unauthenticated);
        Optional<URI> resourceMetadataUrl = parseResourceMetadataUrl(unauthenticated);
        if (resourceMetadataUrl.isEmpty()) {
            return Optional.empty();
        }
        Optional<URI> asMetadataUrl = fetchAsMetadataUrlFromPrm(http, resourceMetadataUrl.get(), probeResponses);
        if (asMetadataUrl.isEmpty()) {
            return Optional.empty();
        }
        return fetchAsMetadata(http, asMetadataUrl.get(), probeResponses);
    }

    private Optional<AuthorizationServerMetadata> discoverViaWellKnownFallback(Http http,
                                                                               HttpService service,
                                                                               List<HttpRequestResponse> probeResponses) {
        String url = OAuthWellKnownPaths.buildUrl(service, OAuthWellKnownPaths.AS_WELL_KNOWN_PATH);
        return fetchAsMetadata(http, URI.create(url), probeResponses);
    }

    private static Optional<URI> parseResourceMetadataUrl(HttpRequestResponse unauthenticated) {
        HttpResponse response = unauthenticated.response();
        if (response == null) {
            return Optional.empty();
        }
        return MetadataParsers.parseResourceMetadataFromWwwAuthenticate(
                response.headerValue(WWW_AUTHENTICATE_HEADER));
    }

    private static Optional<URI> fetchAsMetadataUrlFromPrm(Http http, URI prmUrl,
                                                           List<HttpRequestResponse> probeResponses) {
        HttpRequestResponse prmResponse = http.sendRequest(HttpRequest.httpRequestFromUrl(prmUrl.toString()));
        probeResponses.add(prmResponse);
        HttpResponse response = prmResponse.response();
        if (response == null || response.statusCode() != HTTP_OK) {
            return Optional.empty();
        }
        return MetadataParsers.parseJsonObject(response.bodyToString())
                .flatMap(BurpAuthorizationServerDiscovery::resolveFirstAuthorizationServer);
    }

    private static Optional<URI> resolveFirstAuthorizationServer(JsonNode document) {
        JsonNode servers = document.path("authorization_servers");
        if (!servers.isArray() || servers.isEmpty()) {
            return Optional.empty();
        }
        JsonNode first = servers.get(0);
        if (!first.isTextual()) {
            return Optional.empty();
        }
        try {
            URI asIssuer = URI.create(first.asText());
            return Optional.of(asIssuer.resolve(OAuthWellKnownPaths.AS_WELL_KNOWN_PATH));
        } catch (IllegalArgumentException e) {
            return Optional.empty();
        }
    }

    private static Optional<AuthorizationServerMetadata> fetchAsMetadata(Http http, URI asMetadataUrl,
                                                                         List<HttpRequestResponse> probeResponses) {
        HttpRequestResponse asResponse = http.sendRequest(
                HttpRequest.httpRequestFromUrl(asMetadataUrl.toString()));
        probeResponses.add(asResponse);
        HttpResponse response = asResponse.response();
        if (response == null || response.statusCode() != HTTP_OK) {
            return Optional.empty();
        }
        return MetadataParsers.parseAs(response.bodyToString());
    }
}
