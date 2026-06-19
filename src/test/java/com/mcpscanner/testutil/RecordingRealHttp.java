package com.mcpscanner.testutil;

import burp.api.montoya.core.Registration;
import burp.api.montoya.http.Http;
import burp.api.montoya.http.HttpMode;
import burp.api.montoya.http.RequestOptions;
import burp.api.montoya.http.handler.HttpHandler;
import burp.api.montoya.http.message.HttpHeader;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.api.montoya.http.message.responses.analysis.ResponseKeywordsAnalyzer;
import burp.api.montoya.http.message.responses.analysis.ResponseVariationsAnalyzer;
import burp.api.montoya.http.sessions.CookieJar;
import burp.api.montoya.http.sessions.SessionHandlingAction;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpResponse.BodyHandlers;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

/**
 * Shared test-only {@link Http} implementation that sends real HTTP requests via a
 * {@link java.net.http.HttpClient} and wraps the responses in Burp's {@link HttpRequestResponse}
 * objects (via the factory stubs installed by {@link MontoyaTestFactory}).
 *
 * <p>It consolidates two formerly-duplicated doubles:
 * <ul>
 *   <li>the integration {@code RealHttp} — session-tracking + header normalization (strip
 *       {@code Content-Length}/{@code Host}, inject default {@code Accept}/{@code Content-Type},
 *       lower-cased {@code Mcp-Session-Id} tracking, Title-Cased response header names); and</li>
 *   <li>the OAuth unit-test {@code RecordingHttp} — recording each sent request so tests can assert
 *       which URLs/methods were routed through Burp ({@link #sentUrls} +
 *       {@link #sentMethodsByUrlSuffix(String)}).</li>
 * </ul>
 *
 * <p>All unsupported {@link Http} methods throw {@link UnsupportedOperationException}.
 */
public class RecordingRealHttp implements Http {

    private static final Duration REQUEST_TIMEOUT = Duration.ofSeconds(10);
    private static final String MCP_SESSION_ID_HEADER = "Mcp-Session-Id";

    /** Every URL sent, in order. Exposed for assertions and subclass overrides. */
    public final List<String> sentUrls = Collections.synchronizedList(new ArrayList<>());
    private final List<MethodUrl> sentMethodUrls = Collections.synchronizedList(new ArrayList<>());

    private final HttpClient httpClient;
    /**
     * Tracks the active session ID, simulating the role of the SSE proxy which preserves the
     * session ID on auth-stripped probes. Without this, probes that strip the session ID header
     * would get 400 "Missing session ID" from the server instead of the auth bypass response we
     * want to test.
     */
    private volatile String activeSessionId;

    private record MethodUrl(String method, String url) {}

    /** Default no-arg constructor with a freshly built {@link HttpClient}. */
    public RecordingRealHttp() {
        this(HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(5)).build());
    }

    public RecordingRealHttp(HttpClient httpClient) {
        this.httpClient = httpClient;
    }

    public RecordingRealHttp(HttpClient httpClient, String sessionId) {
        this.httpClient = httpClient;
        this.activeSessionId = sessionId;
    }

    /** Methods of every request sent to a URL ending with {@code suffix}, in order. */
    public List<String> sentMethodsByUrlSuffix(String suffix) {
        synchronized (sentMethodUrls) {
            return sentMethodUrls.stream()
                    .filter(mu -> mu.url().endsWith(suffix))
                    .map(MethodUrl::method)
                    .toList();
        }
    }

    @Override
    public HttpRequestResponse sendRequest(HttpRequest burpRequest) {
        String url = resolveUrl(burpRequest);
        sentUrls.add(url);
        sentMethodUrls.add(new MethodUrl(burpRequest.method(), url));
        try {
            java.net.http.HttpRequest javaRequest = toJavaRequest(burpRequest, url, activeSessionId);
            java.net.http.HttpResponse<byte[]> javaResponse =
                    httpClient.send(javaRequest, BodyHandlers.ofByteArray());
            // Track the session ID from responses so subsequent requests (including
            // auth-stripped probes) can use it — simulates the SSE proxy's role.
            javaResponse.headers().firstValue("mcp-session-id").ifPresent(id -> activeSessionId = id);
            HttpResponse burpResponse = toBurpResponse(javaResponse);
            return HttpRequestResponse.httpRequestResponse(burpRequest, burpResponse);
        } catch (Exception e) {
            return HttpRequestResponse.httpRequestResponse(burpRequest, null);
        }
    }

    @Override
    public HttpRequestResponse sendRequest(HttpRequest request, HttpMode httpMode) {
        return sendRequest(request);
    }

    @Override
    public HttpRequestResponse sendRequest(HttpRequest request, HttpMode httpMode, String connectionId) {
        return sendRequest(request);
    }

    @Override
    public HttpRequestResponse sendRequest(HttpRequest request, RequestOptions requestOptions) {
        return sendRequest(request);
    }

    @Override
    public List<HttpRequestResponse> sendRequests(List<HttpRequest> requests) {
        return requests.stream().map(this::sendRequest).toList();
    }

    @Override
    public List<HttpRequestResponse> sendRequests(List<HttpRequest> requests, HttpMode httpMode) {
        return sendRequests(requests);
    }

    @Override
    public Registration registerHttpHandler(HttpHandler handler) {
        throw new UnsupportedOperationException("registerHttpHandler not supported in RecordingRealHttp");
    }

    @Override
    public Registration registerSessionHandlingAction(SessionHandlingAction sessionHandlingAction) {
        throw new UnsupportedOperationException("registerSessionHandlingAction not supported in RecordingRealHttp");
    }

    @Override
    public ResponseKeywordsAnalyzer createResponseKeywordsAnalyzer(List<String> keywords) {
        throw new UnsupportedOperationException("createResponseKeywordsAnalyzer not supported in RecordingRealHttp");
    }

    @Override
    public ResponseVariationsAnalyzer createResponseVariationsAnalyzer() {
        throw new UnsupportedOperationException("createResponseVariationsAnalyzer not supported in RecordingRealHttp");
    }

    @Override
    public CookieJar cookieJar() {
        throw new UnsupportedOperationException("cookieJar not supported in RecordingRealHttp");
    }

    private static java.net.http.HttpRequest toJavaRequest(HttpRequest burpRequest,
                                                           String url,
                                                           String fallbackSessionId) {
        java.net.http.HttpRequest.Builder builder = java.net.http.HttpRequest.newBuilder(URI.create(url))
                .timeout(REQUEST_TIMEOUT);

        // MontoyaTestFactory mocks return List.of() from headers() regardless of
        // withAddedHeader() calls, so we extract headers via both routes:
        // 1. headers() list (works in production / real Burp)
        // 2. headerValue() for specific known headers (works for test mocks)
        boolean hasContentType = false;
        boolean hasAccept = false;
        boolean hasMcpSession = false;
        boolean hasAuthorization = false;

        for (HttpHeader header : burpRequest.headers()) {
            String name = header.name();
            // Skip pseudo-headers and Host (Java HttpClient manages these)
            if (name.equalsIgnoreCase("Host") || name.startsWith(":")) {
                continue;
            }
            // Skip Content-Length — Java HttpClient sets this from the body
            if (name.equalsIgnoreCase("Content-Length")) {
                continue;
            }
            if (name.equalsIgnoreCase("Content-Type")) hasContentType = true;
            if (name.equalsIgnoreCase("Accept")) hasAccept = true;
            if (name.equalsIgnoreCase("Mcp-Session-Id")) hasMcpSession = true;
            if (name.equalsIgnoreCase("Authorization")) hasAuthorization = true;
            builder.header(name, header.value());
        }

        // Fallback: extract specific headers via headerValue() for mock requests
        if (!hasMcpSession) {
            String sid = burpRequest.headerValue(MCP_SESSION_ID_HEADER);
            if (sid != null) {
                builder.header(MCP_SESSION_ID_HEADER, sid);
                hasMcpSession = true;
            }
        }
        // Inject the tracked active session ID when the probe doesn't have one.
        // This simulates the SSE proxy's role: auth-stripped probes deliberately
        // omit the session ID, but the proxy re-injects it before forwarding upstream.
        if (!hasMcpSession && fallbackSessionId != null) {
            builder.header(MCP_SESSION_ID_HEADER, fallbackSessionId);
        }
        if (!hasAuthorization) {
            String auth = burpRequest.headerValue("Authorization");
            if (auth != null) builder.header("Authorization", auth);
        }

        String body = burpRequest.bodyToString();
        if (!hasContentType && body != null && !body.isEmpty()) {
            builder.header("Content-Type", "application/json");
        }
        if (!hasAccept) {
            builder.header("Accept", "application/json, text/event-stream");
        }

        String method = burpRequest.method();
        if (body != null && !body.isEmpty()) {
            builder.method(method, java.net.http.HttpRequest.BodyPublishers.ofString(body));
        } else {
            builder.method(method, java.net.http.HttpRequest.BodyPublishers.noBody());
        }
        return builder.build();
    }

    /**
     * Reconstruct the request URL from the Burp {@link HttpRequest}.
     *
     * <p>Attempts {@link HttpRequest#url()} first (works in production Burp); falls back to
     * building the URL from {@code httpService()} host/port/secure plus the path header line
     * for mock requests built via the test factory.
     */
    private static String resolveUrl(HttpRequest burpRequest) {
        try {
            String rawUrl = burpRequest.url();
            if (rawUrl != null && !rawUrl.isEmpty()) {
                return rawUrl;
            }
        } catch (Exception ignored) {
        }
        var service = burpRequest.httpService();
        String scheme = service.secure() ? "https" : "http";
        int port = service.port();
        String host = service.host();
        boolean defaultPort = (service.secure() && port == 443) || (!service.secure() && port == 80);
        String authority = defaultPort ? host : host + ":" + port;
        // For test mocks the path isn't tracked; use /mcp as the canonical MCP endpoint path.
        // The probe body already encodes the method; the path just needs to route to the server.
        try {
            String path = burpRequest.path();
            return scheme + "://" + authority + (path != null && !path.isEmpty() ? path : "/mcp");
        } catch (Exception ignored) {
            return scheme + "://" + authority + "/mcp";
        }
    }

    private static HttpResponse toBurpResponse(java.net.http.HttpResponse<byte[]> javaResponse) {
        StringBuilder raw = new StringBuilder();
        raw.append("HTTP/1.1 ").append(javaResponse.statusCode()).append(" \r\n");
        // Normalize header names to Title-Case so MontoyaTestFactory's case-sensitive
        // mock lookup (e.g. headerValue("Content-Type")) works correctly.
        javaResponse.headers().map().forEach((name, values) -> {
            String titleName = toTitleCase(name);
            values.forEach(value -> raw.append(titleName).append(": ").append(value).append("\r\n"));
        });
        raw.append("\r\n");
        String bodyStr = new String(javaResponse.body(), java.nio.charset.StandardCharsets.UTF_8);
        raw.append(bodyStr);
        return HttpResponse.httpResponse(raw.toString());
    }

    private static String toTitleCase(String headerName) {
        if (headerName == null || headerName.isEmpty()) {
            return headerName;
        }
        StringBuilder result = new StringBuilder(headerName.length());
        boolean capitalizeNext = true;
        for (char c : headerName.toCharArray()) {
            if (c == '-') {
                result.append(c);
                capitalizeNext = true;
            } else if (capitalizeNext) {
                result.append(Character.toUpperCase(c));
                capitalizeNext = false;
            } else {
                result.append(Character.toLowerCase(c));
            }
        }
        return result.toString();
    }
}
