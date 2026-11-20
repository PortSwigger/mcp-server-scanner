package com.mcpscanner.http.evidence;

import burp.api.montoya.core.Annotations;
import burp.api.montoya.core.ByteArray;
import burp.api.montoya.http.HttpService;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;

import java.net.URI;
import java.util.Arrays;
import java.util.function.Supplier;

public final class WireRecord {

    private final Supplier<HttpService> service;
    private final byte[] request;
    private final byte[] responseHead;
    private final byte[] responseBody;
    private final boolean bodyFollows;
    private final boolean truncated;

    private WireRecord(Supplier<HttpService> service, byte[] request, byte[] responseHead, byte[] responseBody,
                       boolean bodyFollows, boolean truncated) {
        this.service = service;
        this.request = request;
        this.responseHead = responseHead;
        this.responseBody = responseBody;
        this.bodyFollows = bodyFollows;
        this.truncated = truncated;
    }

    public static WireRecord ofBurp(HttpRequestResponse sent) {
        HttpResponse response = sent.response();
        byte[] whole = response.toByteArray().getBytes();
        int bodyStart = response.bodyOffset();
        HttpService service = sent.request().httpService();
        return new WireRecord(() -> service, sent.request().toByteArray().getBytes(),
                Arrays.copyOfRange(whole, 0, bodyStart), Arrays.copyOfRange(whole, bodyStart, whole.length),
                false, false);
    }

    public static WireRecord ofJdk(java.net.http.HttpRequest request, byte[] requestBody,
                                   java.net.http.HttpResponse<?> head) {
        return new WireRecord(() -> serviceOf(request.uri()), JdkWire.request(request, requestBody),
                JdkWire.responseHead(head), new byte[0], true, false);
    }

    static WireRecord streamEvent(java.net.http.HttpResponse<?> stream, byte[] event) {
        return ofJdk(stream.request(), new byte[0], stream).withBody(event, false);
    }

    public static WireRecord ofSocket(HttpService service, byte[] written, byte[] read, boolean truncatedByCap) {
        int responseStart = WireBytes.finalResponseStart(read);
        int bodyStart = WireBytes.bodyStart(read, responseStart);
        return new WireRecord(() -> service, written.clone(), Arrays.copyOfRange(read, responseStart, bodyStart),
                Arrays.copyOfRange(read, bodyStart, read.length), false, truncatedByCap);
    }

    public static WireRecord unanswered(HttpService service, byte[] written) {
        return new WireRecord(() -> service, written.clone(), null, new byte[0], false, false);
    }

    public static WireRecord unansweredJdk(java.net.http.HttpRequest request, byte[] requestBody) {
        return new WireRecord(() -> serviceOf(request.uri()), JdkWire.request(request, requestBody), null,
                new byte[0], false, false);
    }

    public WireRecord withBodyAsRead(byte[] bodyAsRead, boolean truncatedByCap) {
        return bodyFollows ? withBody(bodyAsRead, truncatedByCap) : this;
    }

    public WireRecord withBody(byte[] body, boolean truncatedByCap) {
        return new WireRecord(service, request, responseHead, body.clone(), false, truncatedByCap);
    }

    public long size() {
        return (long) request.length + (responseHead == null ? 0 : responseHead.length) + responseBody.length;
    }

    public HttpRequestResponse evidence() {
        return HttpRequestResponse.httpRequestResponse(
                HttpRequest.httpRequest(service.get(), ByteArray.byteArray(request)), response(), annotations());
    }

    private HttpResponse response() {
        return responseHead == null ? null
                : HttpResponse.httpResponse(ByteArray.byteArray(WireBytes.joined(responseHead, responseBody)));
    }

    private Annotations annotations() {
        return truncated ? TruncationNote.kept(responseBody.length) : Annotations.annotations();
    }

    private static HttpService serviceOf(URI uri) {
        boolean secure = "https".equalsIgnoreCase(uri.getScheme());
        int port = uri.getPort() == -1 ? (secure ? 443 : 80) : uri.getPort();
        return HttpService.httpService(uri.getHost(), port, secure);
    }
}
