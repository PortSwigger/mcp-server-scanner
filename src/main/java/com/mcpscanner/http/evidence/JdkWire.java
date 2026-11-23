package com.mcpscanner.http.evidence;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpHeaders;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;

final class JdkWire {

    private static final String COOKIE = "Cookie";
    private static final String USER_AGENT = "User-Agent";
    private static final String HOST = "Host";
    private static final int FIRST_RELEASE_OMITTING_BODYLESS_LENGTH = 19;

    private JdkWire() {
    }

    static byte[] request(HttpRequest request, byte[] body) {
        String head = requestLine(request) + systemHeaders(request) + userHeaders(request) + cookieLine(request)
                + "\r\n";
        return WireBytes.joined(head.getBytes(StandardCharsets.US_ASCII), body);
    }

    static byte[] responseHead(HttpResponse<?> response) {
        StringBuilder head = new StringBuilder(versionOf(response.version())).append(' ')
                .append(response.statusCode()).append(' ').append(StatusReasons.of(response.statusCode()))
                .append("\r\n");
        headersOf(response).forEach((name, values) -> {
            if (!name.startsWith(":")) {
                appendLines(head, name, values);
            }
        });
        return head.append("\r\n").toString().getBytes(StandardCharsets.ISO_8859_1);
    }

    private static Map<String, List<String>> headersOf(HttpResponse<?> response) {
        HttpHeaders headers = response.headers();
        return headers == null ? Map.of() : headers.map();
    }

    private static String requestLine(HttpRequest request) {
        return request.method() + ' ' + JdkRequestTarget.of(request.uri()) + " HTTP/1.1\r\n";
    }

    private static String systemHeaders(HttpRequest request) {
        Map<String, String> system = new TreeMap<>(String.CASE_INSENSITIVE_ORDER);
        if (request.headers().firstValue(HOST).isEmpty()) {
            system.put(HOST, hostOf(request.uri()));
        }
        framingOf(request).forEach(system::put);
        if (request.headers().firstValue(USER_AGENT).isEmpty()) {
            system.put(USER_AGENT, "Java-http-client/" + System.getProperty("java.version"));
        }
        StringBuilder lines = new StringBuilder();
        system.forEach((name, value) -> appendLines(lines, name, List.of(value)));
        return lines.toString();
    }

    private static Map<String, String> framingOf(HttpRequest request) {
        return request.bodyPublisher()
                .map(publisher -> framingOf(publisher.contentLength()))
                .orElseGet(JdkWire::framingWithoutPublisher);
    }

    private static Map<String, String> framingOf(long contentLength) {
        return contentLength < 0
                ? Map.of("Transfer-encoding", "chunked")
                : Map.of("Content-Length", Long.toString(contentLength));
    }

    private static Map<String, String> framingWithoutPublisher() {
        return Runtime.version().feature() >= FIRST_RELEASE_OMITTING_BODYLESS_LENGTH
                ? Map.of()
                : Map.of("Content-Length", "0");
    }

    private static String userHeaders(HttpRequest request) {
        StringBuilder lines = new StringBuilder();
        request.headers().map().forEach((name, values) -> {
            if (!COOKIE.equalsIgnoreCase(name)) {
                appendLines(lines, name, values);
            }
        });
        return lines.toString();
    }

    private static String cookieLine(HttpRequest request) {
        List<String> cookies = request.headers().allValues(COOKIE);
        return cookies.isEmpty() ? "" : COOKIE + ": " + String.join("; ", cookies) + "\r\n";
    }

    private static String hostOf(URI uri) {
        int port = uri.getPort();
        boolean secure = "https".equalsIgnoreCase(uri.getScheme());
        boolean defaultPort = port == -1 || port == (secure ? 443 : 80);
        return defaultPort ? uri.getHost() : uri.getHost() + ":" + port;
    }

    private static void appendLines(StringBuilder lines, String name, List<String> values) {
        values.forEach(value -> lines.append(name).append(": ").append(value).append("\r\n"));
    }

    private static String versionOf(HttpClient.Version version) {
        return version == HttpClient.Version.HTTP_2 ? "HTTP/2" : "HTTP/1.1";
    }
}
