package com.mcpscanner.http;

import burp.api.montoya.http.Http;
import burp.api.montoya.http.message.requests.HttpRequest;

final class OffScanQueueHttp extends ForwardingHttp {

    OffScanQueueHttp(Http delegate) {
        super(delegate);
    }

    @Override
    protected HttpRequest outgoing(HttpRequest request) {
        return request;
    }
}
