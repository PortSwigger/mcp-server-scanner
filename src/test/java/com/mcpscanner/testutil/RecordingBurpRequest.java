package com.mcpscanner.testutil;

import burp.api.montoya.core.ByteArray;
import burp.api.montoya.http.HttpService;
import burp.api.montoya.http.message.requests.HttpRequest;

import java.util.ArrayList;
import java.util.List;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

public final class RecordingBurpRequest {

    private final HttpRequest request = mock(HttpRequest.class);
    private final List<String> addedHeaders = new ArrayList<>();
    private String startedUrl;
    private String method;
    private byte[] bodyBytes;

    public RecordingBurpRequest() {
        when(request.withMethod(anyString())).thenAnswer(inv -> {
            method = inv.getArgument(0);
            return request;
        });
        when(request.withAddedHeader(anyString(), anyString())).thenAnswer(inv -> {
            addedHeaders.add(inv.getArgument(0) + ": " + inv.getArgument(1));
            return request;
        });
        when(request.withBody(any(ByteArray.class))).thenAnswer(inv -> {
            bodyBytes = ((ByteArray) inv.getArgument(0)).getBytes();
            return request;
        });
        when(request.toByteArray()).thenAnswer(inv -> ByteArray.byteArray(wire()));
        when(request.httpService()).thenAnswer(inv -> serviceOf(java.net.URI.create(startedUrl)));
        when(request.withBody(anyString())).thenThrow(
                new AssertionError("Body must be set as UTF-8 bytes, never as a platform-encoded String"));
    }

    private static HttpService serviceOf(java.net.URI url) {
        boolean secure = "https".equalsIgnoreCase(url.getScheme());
        return HttpService.httpService(url.getHost(), url.getPort() == -1 ? (secure ? 443 : 80) : url.getPort(), secure);
    }

    private byte[] wire() {
        StringBuilder head = new StringBuilder(String.valueOf(method)).append(' ').append(startedUrl)
                .append(" HTTP/1.1\r\n");
        addedHeaders.forEach(header -> head.append(header).append("\r\n"));
        byte[] start = head.append("\r\n").toString().getBytes(java.nio.charset.StandardCharsets.ISO_8859_1);
        byte[] body = bodyBytes == null ? new byte[0] : bodyBytes;
        byte[] whole = java.util.Arrays.copyOf(start, start.length + body.length);
        System.arraycopy(body, 0, whole, start.length, body.length);
        return whole;
    }

    public HttpRequest startFrom(String url) {
        startedUrl = url;
        return request;
    }

    public HttpRequest request() {
        return request;
    }

    public String startedUrl() {
        return startedUrl;
    }

    public String method() {
        return method;
    }

    public List<String> addedHeaders() {
        return addedHeaders;
    }

    public byte[] bodyBytes() {
        return bodyBytes;
    }
}
