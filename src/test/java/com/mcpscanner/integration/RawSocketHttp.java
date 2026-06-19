package com.mcpscanner.integration;

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
import com.mcpscanner.mcp.BoundedBodyReader;
import com.mcpscanner.mcp.SseResponseParser;

import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Locale;

/**
 * Test-only {@link Http} double that writes the request line + ALL headers verbatim onto a raw TCP
 * socket — including an attacker-controlled {@code Host} header that a {@link java.net.http.HttpClient}
 * would silently strip and manage itself. This is what {@link RecordingRealHttp} cannot do and why
 * the {@code HOST_OVERRIDE} branch of {@link com.mcpscanner.checks.McpActiveDnsRebindingCheck} could
 * not be covered end-to-end before.
 *
 * <p>It mirrors the local SSE proxy's framing: when the upstream replies with
 * {@code Content-Type: text/event-stream}, it lifts the JSON-RPC reply out of the
 * {@code event: message} / {@code data:} frame via {@link SseResponseParser} and hands the check a
 * bounded {@code application/json} response (exactly as {@code SseProxyServer.convertStreamingResponse}
 * does in production). Non-streaming bodies pass through {@link BoundedBodyReader}.
 *
 * <p>Hermetic: only ever talks to the locally-spawned in-repo test-server.
 */
public class RawSocketHttp implements Http {

    private static final int SOCKET_TIMEOUT_MILLIS = 10_000;

    private final String host;
    private final int port;

    public RawSocketHttp(String host, int port) {
        this.host = host;
        this.port = port;
    }

    @Override
    public HttpRequestResponse sendRequest(HttpRequest burpRequest) {
        try {
            byte[] wire = serializeRequest(burpRequest);
            HttpResponse response = exchange(wire);
            return HttpRequestResponse.httpRequestResponse(burpRequest, response);
        } catch (IOException e) {
            return HttpRequestResponse.httpRequestResponse(burpRequest, null);
        }
    }

    /**
     * Builds the raw HTTP/1.1 request bytes. The {@code Host} header — and every other header — is
     * written exactly as the caller set it, so a spoofed {@code Host: attacker.example} reaches the
     * server on the wire. {@code Content-Length} and {@code Connection: close} are normalized so the
     * server frames the body correctly and closes after replying.
     */
    private byte[] serializeRequest(HttpRequest burpRequest) {
        String body = burpRequest.bodyToString();
        body = body == null ? "" : body;
        byte[] bodyBytes = body.getBytes(StandardCharsets.UTF_8);

        StringBuilder head = new StringBuilder();
        head.append(burpRequest.method()).append(' ').append(requestTarget(burpRequest)).append(" HTTP/1.1\r\n");

        boolean hasHost = false;
        boolean hasAccept = false;
        boolean hasContentType = false;
        for (HttpHeader header : burpRequest.headers()) {
            String name = header.name();
            if (name.startsWith(":")) {
                continue;
            }
            if (name.equalsIgnoreCase("Content-Length") || name.equalsIgnoreCase("Connection")) {
                continue;
            }
            if (name.equalsIgnoreCase("Host")) {
                hasHost = true;
            }
            if (name.equalsIgnoreCase("Accept")) {
                hasAccept = true;
            }
            if (name.equalsIgnoreCase("Content-Type")) {
                hasContentType = true;
            }
            head.append(name).append(": ").append(header.value()).append("\r\n");
        }

        if (!hasHost) {
            head.append("Host: ").append(host).append(':').append(port).append("\r\n");
        }
        if (!hasContentType && bodyBytes.length > 0) {
            head.append("Content-Type: application/json\r\n");
        }
        if (!hasAccept) {
            head.append("Accept: application/json, text/event-stream\r\n");
        }
        head.append("Content-Length: ").append(bodyBytes.length).append("\r\n");
        head.append("Connection: close\r\n");
        head.append("\r\n");

        byte[] headBytes = head.toString().getBytes(StandardCharsets.UTF_8);
        byte[] wire = new byte[headBytes.length + bodyBytes.length];
        System.arraycopy(headBytes, 0, wire, 0, headBytes.length);
        System.arraycopy(bodyBytes, 0, wire, headBytes.length, bodyBytes.length);
        return wire;
    }

    private HttpResponse exchange(byte[] wire) throws IOException {
        try (Socket socket = new Socket()) {
            socket.connect(new InetSocketAddress(host, port), SOCKET_TIMEOUT_MILLIS);
            socket.setSoTimeout(SOCKET_TIMEOUT_MILLIS);
            OutputStream out = socket.getOutputStream();
            out.write(wire);
            out.flush();
            byte[] raw = BoundedBodyReader.readUtf8(socket.getInputStream()).getBytes(StandardCharsets.UTF_8);
            return toBurpResponse(raw);
        }
    }

    /**
     * Splits the raw HTTP response into status line / headers / body, then — mirroring the SSE proxy —
     * lifts the JSON-RPC payload out of an {@code event: message} frame when the body is
     * {@code text/event-stream}. The rebuilt response carries a plain {@code Content-Type:
     * application/json} so {@link com.mcpscanner.mcp.McpRequestDetector} can parse it.
     */
    private static HttpResponse toBurpResponse(byte[] raw) throws IOException {
        String full = new String(raw, StandardCharsets.UTF_8);
        int headerEnd = full.indexOf("\r\n\r\n");
        String headerBlock = headerEnd >= 0 ? full.substring(0, headerEnd) : full;
        String body = headerEnd >= 0 ? full.substring(headerEnd + 4) : "";

        if (isEventStream(headerBlock)) {
            String json = liftJsonRpc(body);
            String statusLine = firstLine(headerBlock);
            return HttpResponse.httpResponse(
                    statusLine + "\r\n"
                            + "Content-Type: application/json\r\n\r\n"
                            + (json != null ? json : ""));
        }
        return HttpResponse.httpResponse(full);
    }

    private static String liftJsonRpc(String sseBody) throws IOException {
        try (BufferedReader reader = new BufferedReader(
                new InputStreamReader(streamOf(sseBody), StandardCharsets.UTF_8))) {
            return SseResponseParser.extractJsonRpcResponse(reader);
        }
    }

    private static InputStream streamOf(String value) {
        return new ByteArrayInputStream(value.getBytes(StandardCharsets.UTF_8));
    }

    private static boolean isEventStream(String headerBlock) {
        for (String line : headerBlock.split("\r\n")) {
            int colon = line.indexOf(':');
            if (colon < 0) {
                continue;
            }
            if (line.substring(0, colon).trim().equalsIgnoreCase("Content-Type")
                    && line.substring(colon + 1).toLowerCase(Locale.ROOT).contains("text/event-stream")) {
                return true;
            }
        }
        return false;
    }

    private static String firstLine(String headerBlock) {
        int nl = headerBlock.indexOf("\r\n");
        return nl >= 0 ? headerBlock.substring(0, nl) : headerBlock;
    }

    private static String requestTarget(HttpRequest burpRequest) {
        try {
            String path = burpRequest.path();
            if (path != null && !path.isEmpty()) {
                return path;
            }
        } catch (Exception ignored) {
            // fall through to default
        }
        return "/mcp";
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
        throw new UnsupportedOperationException("registerHttpHandler not supported in RawSocketHttp");
    }

    @Override
    public Registration registerSessionHandlingAction(SessionHandlingAction sessionHandlingAction) {
        throw new UnsupportedOperationException("registerSessionHandlingAction not supported in RawSocketHttp");
    }

    @Override
    public ResponseKeywordsAnalyzer createResponseKeywordsAnalyzer(List<String> keywords) {
        throw new UnsupportedOperationException("createResponseKeywordsAnalyzer not supported in RawSocketHttp");
    }

    @Override
    public ResponseVariationsAnalyzer createResponseVariationsAnalyzer() {
        throw new UnsupportedOperationException("createResponseVariationsAnalyzer not supported in RawSocketHttp");
    }

    @Override
    public CookieJar cookieJar() {
        throw new UnsupportedOperationException("cookieJar not supported in RawSocketHttp");
    }
}
