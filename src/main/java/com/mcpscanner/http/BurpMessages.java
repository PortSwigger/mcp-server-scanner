package com.mcpscanner.http;

import burp.api.montoya.core.ByteArray;
import burp.api.montoya.http.message.HttpHeader;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.function.Function;

public final class BurpMessages {

    private static final String TRANSFER_ENCODING = "Transfer-Encoding";

    private final Function<String, HttpRequest> requestStarter;

    public BurpMessages() {
        this(BareRequests::fromUrl);
    }

    public BurpMessages(Function<String, HttpRequest> requestStarter) {
        this.requestStarter = requestStarter;
    }

    public HttpRequest toRequest(String url, String method, Map<String, List<String>> headers, String body) {
        HttpRequest request = startRequest(url, method, headers);
        return body == null ? request : request.withBody(ByteArray.byteArray(body.getBytes(StandardCharsets.UTF_8)));
    }

    public static boolean bodyWithin(HttpResponse response, int maxBytes) {
        ByteArray body = response.body();
        return body == null || body.length() <= maxBytes;
    }

    public static byte[] unframedBody(HttpResponse response) {
        ByteArray body = response.body();
        return body == null ? new byte[0] : ChunkedBody.unframe(transferEncodings(response), body.getBytes());
    }

    private static List<String> transferEncodings(HttpResponse response) {
        return response.headers().stream()
                .filter(header -> header.name().equalsIgnoreCase(TRANSFER_ENCODING))
                .map(HttpHeader::value)
                .toList();
    }

    public static Map<String, List<String>> multiValued(Map<String, String> headers) {
        Map<String, List<String>> grouped = new LinkedHashMap<>();
        headers.forEach((name, value) -> grouped.put(name, List.of(value)));
        return grouped;
    }

    public static Map<String, List<String>> groupedHeaders(HttpResponse response) {
        Map<String, List<String>> grouped = new LinkedHashMap<>();
        for (HttpHeader header : response.headers()) {
            grouped.computeIfAbsent(header.name(), name -> new ArrayList<>()).add(header.value());
        }
        return grouped;
    }

    private HttpRequest startRequest(String url, String method, Map<String, List<String>> headers) {
        return withHeaders(requestStarter.apply(url).withMethod(method), ConnectionClose.without(headers));
    }

    private static HttpRequest withHeaders(HttpRequest request, Map<String, List<String>> headers) {
        HttpRequest result = request;
        for (Map.Entry<String, List<String>> header : headers.entrySet()) {
            for (String value : header.getValue()) {
                result = result.withAddedHeader(header.getKey(), value);
            }
        }
        return result;
    }
}
