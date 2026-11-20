package com.mcpscanner.checks.catalog.jwtvalidation;

import burp.api.montoya.http.Http;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import com.mcpscanner.testutil.SpentRateLimitQuota;
import com.mcpscanner.testutil.ImmutableHttpRequest;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.function.Predicate;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

final class FakeJwtServer {

    static final String ENDPOINT = "https://mcp.example/mcp";
    static final String TOOL_CALL = "{\"jsonrpc\":\"2.0\",\"id\":7,\"method\":\"tools/call\","
            + "\"params\":{\"name\":\"read_secret\",\"arguments\":{}}}";
    static final String TOOLS_LIST = "{\"jsonrpc\":\"2.0\",\"id\":7,\"method\":\"tools/list\",\"params\":{}}";
    static final String SECRET = "{\"jsonrpc\":\"2.0\",\"id\":7,\"result\":"
            + "{\"content\":[{\"type\":\"text\",\"text\":\"s3cr3t\"}],\"isError\":false}}";
    static final String CATALOG = "{\"jsonrpc\":\"2.0\",\"id\":7,\"result\":{\"tools\":[{\"name\":\"read_secret\"}]}}";

    private final String liveToken;
    private final List<Predicate<String>> acceptedForgeries = new ArrayList<>();
    private final Map<String, String> documents = new HashMap<>();
    private final List<HttpRequest> received = new ArrayList<>();
    private boolean anonymousAllowed;
    private boolean anyBearerAllowed;
    private boolean claimsIgnored;
    private int openAfterRequests = Integer.MAX_VALUE;
    private int throttleAfterRequests = Integer.MAX_VALUE;
    private int quotaSpentAfterRequests = Integer.MAX_VALUE;
    private String operationResult = SECRET;
    private String forgeryResult;

    FakeJwtServer(String liveToken) {
        this.liveToken = liveToken;
    }

    FakeJwtServer accepting(Predicate<String> forgery) {
        acceptedForgeries.add(forgery);
        return this;
    }

    FakeJwtServer allowingAnonymous() {
        anonymousAllowed = true;
        return this;
    }

    FakeJwtServer allowingAnyBearer() {
        anyBearerAllowed = true;
        return this;
    }

    FakeJwtServer openToEveryoneAfter(int requests) {
        openAfterRequests = requests;
        return this;
    }

    FakeJwtServer throttlingAfter(int requests) {
        throttleAfterRequests = requests;
        return this;
    }

    FakeJwtServer spendingQuotaAfter(int requests) {
        quotaSpentAfterRequests = requests;
        return this;
    }

    FakeJwtServer ignoringClaims() {
        claimsIgnored = true;
        return this;
    }

    FakeJwtServer answering(String result) {
        operationResult = result;
        return this;
    }

    FakeJwtServer answeringForgeries(String result) {
        forgeryResult = result;
        return this;
    }

    FakeJwtServer publishing(String url, String json) {
        documents.put(url, json);
        return this;
    }

    List<HttpRequest> received() {
        return received;
    }

    List<String> bearersReceived() {
        return received.stream().map(request -> request.headerValue("Authorization"))
                .filter(value -> value != null).map(value -> value.substring("Bearer ".length())).toList();
    }

    Http http() {
        Http http = mock(Http.class);
        when(http.sendRequest(any(HttpRequest.class))).thenAnswer(invocation -> answer(invocation.getArgument(0)));
        return http;
    }

    static HttpRequestResponse seed(String body, String authorization) {
        Map<String, String> headers = authorization == null
                ? Map.of("Content-Type", "application/json")
                : Map.of("Content-Type", "application/json", "Authorization", authorization);
        HttpRequest request = ImmutableHttpRequest.post(ENDPOINT, headers, body);
        return HttpRequestResponse.httpRequestResponse(request, response(200, SECRET));
    }

    private HttpRequestResponse answer(HttpRequest request) {
        received.add(request);
        return HttpRequestResponse.httpRequestResponse(request, reply(request));
    }

    private HttpResponse reply(HttpRequest request) {
        if (received.size() > throttleAfterRequests) {
            return respond(429, "{}");
        }
        if ("GET".equals(request.method())) {
            String document = documents.get(request.url());
            return document == null ? respond(404, "{}") : respond(200, document);
        }
        String authorization = request.headerValue("Authorization");
        if (!authorised(authorization)) {
            return respond(401, "{\"error\":\"invalid_token\"}");
        }
        boolean live = authorization != null && authorization.equals("Bearer " + liveToken);
        return respond(200, live || forgeryResult == null ? operationResult : forgeryResult);
    }

    private HttpResponse respond(int status, String body) {
        String quotaHeaders = received.size() > quotaSpentAfterRequests
                ? SpentRateLimitQuota.HEADER_LINES
                : "";
        return response(status, quotaHeaders, body);
    }

    private boolean authorised(String authorization) {
        if (received.size() > openAfterRequests) {
            return true;
        }
        if (authorization == null) {
            return anonymousAllowed;
        }
        String token = authorization.substring("Bearer ".length());
        if (token.equals(liveToken) || anyBearerAllowed) {
            return true;
        }
        return acceptedForgeries.stream().anyMatch(accepted -> accepted.test(token))
                && CompactJwt.parse(token).filter(jwt -> claimsIgnored || claimsValid(jwt)).isPresent();
    }

    private boolean claimsValid(CompactJwt jwt) {
        CompactJwt live = CompactJwt.parse(liveToken).orElseThrow();
        return jwt.claims().path("iss").equals(live.claims().path("iss"))
                && jwt.claims().path("aud").equals(live.claims().path("aud"))
                && jwt.claims().path("exp").asLong() > System.currentTimeMillis() / 1000;
    }

    static HttpResponse response(int status, String body) {
        return response(status, "", body);
    }

    private static HttpResponse response(int status, String extraHeaders, String body) {
        return HttpResponse.httpResponse("HTTP/1.1 " + status + " X\r\nContent-Type: application/json\r\n"
                + extraHeaders + "\r\n" + body);
    }

    static Predicate<String> algorithm(String algorithm) {
        return token -> CompactJwt.parse(token).filter(jwt -> jwt.algorithm().equals(algorithm)).isPresent();
    }

    static Predicate<String> hmacSignedWith(byte[] key) {
        return algorithm("HS256").and(token -> signedWith(token, key));
    }

    static boolean signedWith(String token, byte[] key) {
        String[] parts = token.split("\\.", -1);
        return parts.length == 3 && parts[2].equals(JwtSegments.encode(HmacSha256.digest(key,
                (parts[0] + "." + parts[1]).getBytes(StandardCharsets.US_ASCII))));
    }
}
