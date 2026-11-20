package com.mcpscanner.proxy;

import java.net.http.HttpResponse;

final class RecordedPostBodies implements HttpResponse.BodyHandler<String> {

    private volatile BoundedPostBodySubscriber latest = new BoundedPostBodySubscriber();

    @Override
    public HttpResponse.BodySubscriber<String> apply(HttpResponse.ResponseInfo responseInfo) {
        latest = new BoundedPostBodySubscriber();
        return latest;
    }

    byte[] lastReceived() {
        return latest.received();
    }
}
