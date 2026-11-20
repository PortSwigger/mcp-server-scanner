package com.mcpscanner.http;

import burp.api.montoya.http.Http;
import burp.api.montoya.http.HttpMode;
import burp.api.montoya.http.RequestOptions;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;

final class ScanQueueBypassingHttp extends ForwardingHttp {

    private final Http unqueued;

    ScanQueueBypassingHttp(Http scan, Http unqueued) {
        super(scan);
        this.unqueued = unqueued;
    }

    @Override
    protected HttpRequest outgoing(HttpRequest request) {
        return request;
    }

    @Override
    public HttpRequestResponse sendRequest(HttpRequest request) {
        return OutsideScanQueue.requested() ? unqueued.sendRequest(request) : super.sendRequest(request);
    }

    @Override
    public HttpRequestResponse sendRequest(HttpRequest request, HttpMode httpMode) {
        return OutsideScanQueue.requested()
                ? unqueued.sendRequest(request, httpMode) : super.sendRequest(request, httpMode);
    }

    @Override
    public HttpRequestResponse sendRequest(HttpRequest request, HttpMode httpMode, String connectionId) {
        return OutsideScanQueue.requested()
                ? unqueued.sendRequest(request, httpMode, connectionId)
                : super.sendRequest(request, httpMode, connectionId);
    }

    @Override
    public HttpRequestResponse sendRequest(HttpRequest request, RequestOptions requestOptions) {
        return OutsideScanQueue.requested()
                ? unqueued.sendRequest(request, requestOptions) : super.sendRequest(request, requestOptions);
    }
}
