package com.mcpscanner.checks.catalog.oauthauthorizationconsent;

import burp.api.montoya.http.message.requests.HttpRequest;
import com.mcpscanner.checks.shared.oauth.ScriptedHttp;

import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.BrokenBarrierException;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CyclicBarrier;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.function.Function;
import java.util.function.Predicate;
import java.util.stream.Collectors;

import static com.mcpscanner.checks.shared.oauth.ScriptedHttp.json;
import static com.mcpscanner.checks.shared.oauth.ScriptedHttp.queryParameter;
import static com.mcpscanner.checks.shared.oauth.ScriptedHttp.redirect;

final class ConsentServer {

    static final String ORIGIN = "https://mcp.example.com";
    static final String MCP = ORIGIN + "/mcp";
    static final String AUTHORIZE = ORIGIN + "/authorize";
    static final String REGISTER = ORIGIN + "/register";
    static final String TOKEN = ORIGIN + "/token";
    static final String CLIENT_SECRET = "probe-secret";
    static final String REVOKE = ORIGIN + "/revoke";
    static final String CLIENT_URI = ORIGIN + "/register/probe-client";
    static final String CLIENT_ID = "probe-client";
    private static final String TOOLS_RESULT = "{\"jsonrpc\":\"2.0\",\"id\":%s,\"result\":{\"tools\":[]}}";
    static final String SCANNER_CREDENTIAL = "Bearer scanner-token";
    static final String SCANNER_SESSION = "scanner-session";
    private static final String UNAUTHORIZED = "HTTP/1.1 401 Unauthorized\r\nWWW-Authenticate: Bearer\r\n"
            + "Content-Type: application/json\r\n\r\n{\"error\":\"invalid_token\"}";

    private final ScriptedHttp http = new ScriptedHttp();
    private final AtomicInteger issuedCodes = new AtomicInteger();
    private final Map<String, AtomicInteger> redemptions = new ConcurrentHashMap<>();
    private Function<String, Integer> redemptionLimit = code -> 1;
    private boolean endpointOpen;
    private Predicate<String> tokenWorks = token -> true;
    private String anonymousRefusal = UNAUTHORIZED;
    private final Map<String, String> challenges = new ConcurrentHashMap<>();
    private final Map<String, String> sessionOwners = new ConcurrentHashMap<>();
    private final Map<String, Boolean> initializedSessions = new ConcurrentHashMap<>();
    private Optional<CyclicBarrier> laterRedemptionsBarrier = Optional.empty();
    private boolean sessionsRequired;
    private boolean cachedTokenResponses;
    private final AtomicInteger issuedSessions = new AtomicInteger();
    private Predicate<HttpRequest> clientAuthenticated = request -> true;

    ConsentServer() {
        http.on("GET", ORIGIN + "/.well-known/oauth-authorization-server", json(200, "{\"issuer\":\"" + ORIGIN + "\","
                        + "\"authorization_endpoint\":\"" + AUTHORIZE + "\",\"registration_endpoint\":\"" + REGISTER
                        + "\",\"token_endpoint\":\"" + TOKEN + "\",\"revocation_endpoint\":\"" + REVOKE + "\"}"))
                .on("POST", REGISTER, request -> json(201, "{\"client_id\":\"" + CLIENT_ID + "\","
                        + "\"redirect_uris\":" + request.bodyToString().replaceAll(".*\"redirect_uris\":(\\[[^]]*]).*", "$1")
                        + ",\"registration_client_uri\":\"" + CLIENT_URI + "\",\"registration_access_token\":\"rat\"}"))
                .on("DELETE", CLIENT_URI, ScriptedHttp.status(204))
                .on("POST", TOKEN, this::redeem)
                .on("POST", MCP, this::answerMcp)
                .on("POST", REVOKE, ScriptedHttp.status(200));
        approveEveryAuthorization();
    }

    ScriptedHttp http() {
        return http;
    }

    ConsentServer approveEveryAuthorization() {
        return authorizeWith(this::issueCode);
    }

    ConsentServer authorizeWith(Function<HttpRequest, String> responder) {
        http.on("GET", AUTHORIZE, responder);
        return this;
    }

    ConsentServer route(String method, String url, Function<HttpRequest, String> responder) {
        http.on(method, url, responder);
        return this;
    }

    ConsentServer openEndpoint() {
        endpointOpen = true;
        return this;
    }

    ConsentServer requireRefreshGrantAtRegistration() {
        Function<HttpRequest, String> accepting = http.responderFor("POST", REGISTER);
        http.on("POST", REGISTER, request -> request.bodyToString().contains("refresh_token")
                ? accepting.apply(request)
                : json(400, "{\"error\":\"invalid_client_metadata\"}"));
        return this;
    }

    ConsentServer issueConfidentialClients(String tokenEndpointAuthMethod, Predicate<HttpRequest> authenticated) {
        http.on("POST", REGISTER, request -> json(201, "{\"client_id\":\"" + CLIENT_ID + "\","
                + "\"client_secret\":\"" + CLIENT_SECRET + "\",\"token_endpoint_auth_method\":\""
                + tokenEndpointAuthMethod + "\",\"redirect_uris\":"
                + request.bodyToString().replaceAll(".*\"redirect_uris\":(\\[[^]]*]).*", "$1") + "}"));
        clientAuthenticated = authenticated;
        return this;
    }

    ConsentServer cacheTokenResponses() {
        cachedTokenResponses = true;
        return this;
    }

    ConsentServer requireSessions() {
        sessionsRequired = true;
        return this;
    }

    ConsentServer rejectIssuedTokens() {
        tokenWorks = token -> false;
        return this;
    }

    ConsentServer honourOnlyTheFirstTokenPerCode() {
        tokenWorks = token -> token.endsWith("-1");
        return this;
    }

    ConsentServer failAnonymousRequestsWithoutAnAuthenticationChallenge() {
        anonymousRefusal = json(400, "{\"jsonrpc\":\"2.0\",\"id\":null,\"error\":{\"code\":-32600,"
                + "\"message\":\"Invalid request parameters\"}}");
        return this;
    }

    ConsentServer requireLaterRedemptionsToOverlap(int redemptions) {
        laterRedemptionsBarrier = Optional.of(new CyclicBarrier(redemptions));
        return this;
    }

    ConsentServer signInAnonymousVisitors() {
        authorizeWith(request -> "sid=fresh".equals(request.headerValue("Cookie"))
                ? issueCode(request)
                : redirect("/login?return=" + request.url().substring(request.url().indexOf('?') + 1)));
        return route("GET", ORIGIN + "/login", request -> "HTTP/1.1 302 Found\r\nSet-Cookie: sid=fresh; Path=/; "
                + "HttpOnly\r\nLocation: " + AUTHORIZE + "?"
                + request.url().substring(request.url().indexOf("return=") + 7) + "\r\n\r\n");
    }

    ConsentServer redeemEveryCodeUpTo(int times) {
        redemptionLimit = code -> times;
        return this;
    }

    ConsentServer redeemLaterCodesUpTo(int times) {
        redemptionLimit = code -> code.equals("code-1") ? 1 : times;
        return this;
    }

    String issueCode(HttpRequest authorization) {
        String code = "code-" + issuedCodes.incrementAndGet();
        challenges.put(code, queryParameter(authorization, "code_challenge"));
        return redirect(queryParameter(authorization, "redirect_uri") + "?code=" + code
                + "&state=" + queryParameter(authorization, "state"));
    }

    int redemptionsOf(String code) {
        return redemptions.getOrDefault(code, new AtomicInteger()).get();
    }

    List<HttpRequest> authorizationRequests() {
        return http.sentTo(AUTHORIZE);
    }

    private String redeem(HttpRequest request) {
        if (!clientAuthenticated.test(request)) {
            return json(401, "{\"error\":\"invalid_client\",\"error_description\":\"client_secret is required\"}");
        }
        Map<String, String> form = form(request.bodyToString());
        String code = form.getOrDefault("code", "");
        int redemption = redemptions.computeIfAbsent(code, ignored -> new AtomicInteger()).incrementAndGet();
        if (!code.equals("code-1") && !overlapped()) {
            return json(400, "{\"error\":\"invalid_grant\",\"error_description\":\"redemptions did not overlap\"}");
        }
        if (redemption > redemptionLimit.apply(code) || !verifies(form.get("code_verifier"), challenges.get(code))) {
            return json(400, "{\"error\":\"invalid_grant\"}");
        }
        String token = cachedTokenResponses ? "token-" + code : "token-" + code + "-" + redemption;
        return json(200, "{\"access_token\":\"" + token + "\",\"refresh_token\":\"refresh-" + token
                + "\",\"token_type\":\"Bearer\"}");
    }

    private boolean overlapped() {
        try {
            laterRedemptionsBarrier.ifPresent(ConsentServer::awaitOthers);
            return true;
        } catch (IllegalStateException alone) {
            return false;
        }
    }

    private static void awaitOthers(CyclicBarrier barrier) {
        try {
            barrier.await(2, TimeUnit.SECONDS);
        } catch (InterruptedException | BrokenBarrierException | TimeoutException alone) {
            throw new IllegalStateException(alone);
        }
    }

    private static boolean verifies(String verifier, String challenge) {
        if (verifier == null || challenge == null) {
            return false;
        }
        try {
            byte[] digest = MessageDigest.getInstance("SHA-256").digest(verifier.getBytes(StandardCharsets.US_ASCII));
            return Base64.getUrlEncoder().withoutPadding().encodeToString(digest).equals(challenge);
        } catch (NoSuchAlgorithmException impossible) {
            throw new IllegalStateException(impossible);
        }
    }

    private String answerMcp(HttpRequest request) {
        if (SCANNER_SESSION.equals(request.headerValue("Mcp-Session-Id"))) {
            return json(404, "{\"jsonrpc\":\"2.0\",\"id\":null,\"error\":{\"code\":-32001,"
                    + "\"message\":\"Session not found\"}}");
        }
        String authorization = request.headerValue("Authorization");
        if (!admits(authorization)) {
            return authorization == null ? anonymousRefusal : UNAUTHORIZED;
        }
        if (sessionsRequired) {
            return answerInSession(request);
        }
        String id = request.bodyToString().replaceAll("(?s).*\"id\"\\s*:\\s*(\\d+).*", "$1");
        return json(200, TOOLS_RESULT.formatted(id));
    }

    private boolean admits(String authorization) {
        if (endpointOpen || SCANNER_CREDENTIAL.equals(authorization)) {
            return true;
        }
        return authorization != null && authorization.startsWith("Bearer token-code-")
                && tokenWorks.test(authorization.substring("Bearer ".length()));
    }

    private String answerInSession(HttpRequest request) {
        String body = request.bodyToString();
        String owner = String.valueOf(request.headerValue("Authorization"));
        if (body.contains("\"method\":\"initialize\"")) {
            String session = "session-" + issuedSessions.incrementAndGet();
            sessionOwners.put(session, owner);
            return "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nMcp-Session-Id: " + session
                    + "\r\n\r\n{\"jsonrpc\":\"2.0\",\"id\":\"init\",\"result\":{}}";
        }
        String session = request.headerValue("Mcp-Session-Id");
        boolean ownSession = session != null && owner.equals(sessionOwners.get(session));
        if (!body.contains("\"id\"")) {
            if (ownSession && body.contains("notifications/initialized")) {
                initializedSessions.put(session, true);
            }
            return ScriptedHttp.status(202);
        }
        if (!ownSession || !initializedSessions.containsKey(session)) {
            return json(400, "{\"jsonrpc\":\"2.0\",\"id\":null,\"error\":{\"code\":-32600,"
                    + "\"message\":\"Bad Request: Missing Mcp-Session-Id header\"}}");
        }
        String id = body.replaceAll("(?s).*\"id\"\\s*:\\s*(\\d+).*", "$1");
        return json(200, TOOLS_RESULT.formatted(id));
    }

    private static Map<String, String> form(String body) {
        return Arrays.stream(body.split("&"))
                .map(pair -> pair.split("=", 2))
                .filter(pair -> pair.length == 2)
                .collect(Collectors.toMap(pair -> decode(pair[0]), pair -> decode(pair[1]), (first, second) -> first));
    }

    private static String decode(String value) {
        return URLDecoder.decode(value, StandardCharsets.UTF_8);
    }
}
