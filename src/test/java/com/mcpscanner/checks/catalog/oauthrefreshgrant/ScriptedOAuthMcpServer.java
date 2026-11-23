package com.mcpscanner.checks.catalog.oauthrefreshgrant;

import burp.api.montoya.http.Http;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

import java.net.URI;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.TreeSet;
import java.util.stream.Collectors;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.mock;

final class ScriptedOAuthMcpServer {

    static final String ORIGIN = "https://as.example";
    static final String MCP_URL = "https://mcp.example/mcp";
    static final String CLIENT_ID = "client-1";
    static final String CLIENT_SECRET = "client-secret-value";
    static final String LIVE_REFRESH_TOKEN = "live-refresh-token-0";
    static final String ORIGINAL_SCOPE = "mcp:tools";

    private static final ObjectMapper JSON = new ObjectMapper();

    boolean acceptsMissingSecret;
    boolean acceptsWrongSecret;
    boolean expandsScope;
    boolean rotatesRefreshTokens;
    boolean declaresScope = true;
    boolean declaresScopeOnlyOnProbes;
    boolean refusesEveryRefresh;
    boolean acceptsUnissuedRefreshTokens;
    boolean mcpEndpointOpenToAnonymous;
    boolean mcpEndpointRefusesProbeTokens;
    boolean mcpEndpointRefusesTokensIssuedWithoutSecret;
    int staleRefreshTokenPresentations;
    boolean servesMetadata = true;
    boolean throttlesMetadata;
    boolean throttlesTokens;
    boolean revokesPreviousAccessTokens;
    String tokenSuffix = "";
    String metadataIssuer = ORIGIN;
    String clientSecret = CLIENT_SECRET;
    List<String> scopesSupported = List.of("mcp:tools", "mcp:admin", "openid");
    List<String> authMethodsSupported = List.of("client_secret_basic");

    final List<Map<String, String>> tokenRequests = new ArrayList<>();
    final List<String> tokenAuthorizations = new ArrayList<>();
    final List<HttpRequest> mcpRequests = new ArrayList<>();
    private final Map<String, String> refreshTokens = new HashMap<>();
    private final Map<String, String> accessTokens = new HashMap<>();
    private final Set<String> probeTokens = new java.util.HashSet<>();
    private final Set<String> secretlessTokens = new java.util.HashSet<>();
    private int issued;

    ScriptedOAuthMcpServer() {
        refreshTokens.put(LIVE_REFRESH_TOKEN, ORIGINAL_SCOPE);
        accessTokens.put("live-access-token-0", ORIGINAL_SCOPE);
    }

    Http http() {
        Http http = mock(Http.class);
        lenient().when(http.sendRequest(any(HttpRequest.class)))
                .thenAnswer(invocation -> handle(invocation.getArgument(0)));
        return http;
    }

    boolean refreshTokenIsLive(String refreshToken) {
        return refreshTokens.containsKey(refreshToken);
    }

    Optional<String> scopeOfAccessToken(String accessToken) {
        return Optional.ofNullable(accessTokens.get(accessToken));
    }

    List<Map<String, String>> requestsWithoutSecret() {
        List<Map<String, String>> withoutSecret = new ArrayList<>();
        for (int i = 0; i < tokenRequests.size(); i++) {
            if (tokenAuthorizations.get(i) == null && !"unissued".equals(tokenRequests.get(i).get("kind"))) {
                withoutSecret.add(tokenRequests.get(i));
            }
        }
        return withoutSecret;
    }

    private HttpRequestResponse handle(HttpRequest request) {
        String path = URI.create(request.url()).getPath();
        HttpResponse response;
        if (path.startsWith("/.well-known/oauth-authorization-server")) {
            response = throttlesMetadata ? json(429, Map.of())
                    : servesMetadata ? json(200, metadata()) : json(404, Map.of("error", "not_found"));
        } else if (path.equals("/token") && throttlesTokens) {
            response = json(429, Map.of());
        } else if (path.equals("/token")) {
            response = token(request);
        } else if (path.equals("/mcp")) {
            response = mcp(request);
        } else {
            response = json(404, Map.of("error", "not_found"));
        }
        return HttpRequestResponse.httpRequestResponse(request, response);
    }

    private Map<String, Object> metadata() {
        Map<String, Object> metadata = new LinkedHashMap<>();
        metadata.put("issuer", metadataIssuer);
        metadata.put("token_endpoint", ORIGIN + "/token");
        metadata.put("scopes_supported", scopesSupported);
        metadata.put("token_endpoint_auth_methods_supported", authMethodsSupported);
        return metadata;
    }

    private HttpResponse token(HttpRequest request) {
        Map<String, String> form = form(request.bodyToString());
        String authorization = request.headerValue("Authorization");
        tokenRequests.add(form);
        tokenAuthorizations.add(authorization);
        String[] credentials = basic(authorization);
        String clientId = credentials != null ? credentials[0] : form.get("client_id");
        String secret = credentials != null ? credentials[1] : form.get("client_secret");
        String grantScope = refreshTokens.get(form.get("refresh_token"));
        if (grantScope == null && !"unissued".equals(form.get("kind"))) {
            staleRefreshTokenPresentations++;
        }
        if (grantScope == null && acceptsUnissuedRefreshTokens) {
            grantScope = ORIGINAL_SCOPE;
        }
        if (refusesEveryRefresh || grantScope == null || !CLIENT_ID.equals(clientId)) {
            return json(400, Map.of("error", "invalid_grant"));
        }
        if (!clientAuthenticated(secret)) {
            return json(401, Map.of("error", "invalid_client"));
        }
        String scope = grantedScope(grantScope, form.get("scope"));
        if (scope == null) {
            return json(400, Map.of("error", "invalid_scope"));
        }
        boolean probe = !clientAuthenticatedCorrectly(secret) || !scopes(scope).equals(scopes(grantScope));
        Map<String, Object> issuedBody = issue(form.get("refresh_token"), scope, probe);
        if (secret == null || secret.isEmpty()) {
            secretlessTokens.add((String) issuedBody.get("access_token"));
        }
        return json(200, issuedBody);
    }

    private boolean clientAuthenticatedCorrectly(String secret) {
        return clientSecret == null || clientSecret.equals(secret);
    }

    private boolean clientAuthenticated(String secret) {
        if (clientSecret == null) {
            return true;
        }
        if (secret == null || secret.isEmpty()) {
            return acceptsMissingSecret;
        }
        return clientSecret.equals(secret) || acceptsWrongSecret;
    }

    private String grantedScope(String original, String requested) {
        if (requested == null) {
            return original;
        }
        Set<String> originalSet = scopes(original);
        Set<String> requestedSet = scopes(requested);
        if (originalSet.containsAll(requestedSet) || expandsScope) {
            return String.join(" ", new TreeSet<>(requestedSet));
        }
        return null;
    }

    private Map<String, Object> issue(String presentedRefreshToken, String scope, boolean probe) {
        issued++;
        String accessToken = "issued-access-token-" + issued + tokenSuffix;
        if (revokesPreviousAccessTokens) {
            accessTokens.clear();
        }
        accessTokens.put(accessToken, scope);
        if (probe) {
            probeTokens.add(accessToken);
        }
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("access_token", accessToken);
        body.put("token_type", "Bearer");
        body.put("expires_in", 600);
        if (declaresScope && (probe || !declaresScopeOnlyOnProbes)) {
            body.put("scope", scope);
        }
        if (rotatesRefreshTokens) {
            String rotated = "rotated-refresh-token-" + issued + tokenSuffix;
            refreshTokens.remove(presentedRefreshToken);
            refreshTokens.put(rotated, scope);
            body.put("refresh_token", rotated);
        }
        return body;
    }

    private HttpResponse mcp(HttpRequest request) {
        mcpRequests.add(request);
        JsonNode body = read(request.bodyToString());
        long id = body.path("id").asLong();
        String authorization = request.headerValue("Authorization");
        boolean authenticated = authorization != null && authorization.startsWith("Bearer ")
                && accessTokens.containsKey(authorization.substring("Bearer ".length()))
                && !(mcpEndpointRefusesProbeTokens && probeTokens.contains(authorization.substring("Bearer ".length())))
                && !(mcpEndpointRefusesTokensIssuedWithoutSecret
                        && secretlessTokens.contains(authorization.substring("Bearer ".length())));
        if (!authenticated && !mcpEndpointOpenToAnonymous) {
            return json(401, Map.of("error", "unauthorized"));
        }
        return json(200, Map.of("jsonrpc", "2.0", "id", id,
                "result", Map.of("tools", List.of(Map.of("name", "read_note")))));
    }

    private static String[] basic(String authorization) {
        if (authorization == null || !authorization.startsWith("Basic ")) {
            return null;
        }
        String decoded = new String(Base64.getDecoder().decode(authorization.substring(6)), StandardCharsets.UTF_8);
        String[] pair = decoded.split(":", 2);
        return new String[]{decode(pair[0]), decode(pair[1])};
    }

    private static Map<String, String> form(String body) {
        Map<String, String> form = new LinkedHashMap<>();
        for (String pair : body.split("&")) {
            String[] parts = pair.split("=", 2);
            form.put(decode(parts[0]), parts.length > 1 ? decode(parts[1]) : "");
        }
        if (form.getOrDefault("refresh_token", "").startsWith("mcp-scanner-unissued-")) {
            form.put("kind", "unissued");
        }
        return form;
    }

    private static Set<String> scopes(String scope) {
        return new LinkedHashSet<>(Arrays.asList(scope.trim().split("\\s+")));
    }

    private static String decode(String value) {
        return URLDecoder.decode(value, StandardCharsets.UTF_8);
    }

    private static JsonNode read(String body) {
        try {
            return JSON.readTree(body);
        } catch (Exception e) {
            return JSON.createObjectNode();
        }
    }

    private static HttpResponse json(int status, Object body) {
        try {
            return HttpResponse.httpResponse("HTTP/1.1 " + status + " X\r\nContent-Type: application/json\r\n\r\n"
                    + JSON.writeValueAsString(body));
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }

    static String describe(List<Map<String, String>> requests) {
        return requests.stream().map(Map::toString).collect(Collectors.joining("; "));
    }
}
