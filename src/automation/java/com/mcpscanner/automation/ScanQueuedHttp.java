package com.mcpscanner.automation;

import burp.api.montoya.http.Http;
import burp.api.montoya.http.HttpMode;
import burp.api.montoya.http.RequestOptions;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import com.mcpscanner.http.ForwardingHttp;

import java.time.Duration;
import java.util.function.Consumer;

public final class ScanQueuedHttp extends ForwardingHttp {

    private final Duration queueWait;
    private final Consumer<Duration> pause;

    ScanQueuedHttp(Http delegate, Duration queueWait, Consumer<Duration> pause) {
        super(delegate);
        this.queueWait = queueWait;
        this.pause = pause;
    }

    public static Http sleeping(Http delegate, Duration queueWait) {
        return new ScanQueuedHttp(delegate, queueWait, ScanQueuedHttp::sleep);
    }

    @Override
    public HttpRequestResponse sendRequest(HttpRequest request) {
        pause.accept(queueWait);
        return super.sendRequest(request);
    }

    @Override
    public HttpRequestResponse sendRequest(HttpRequest request, HttpMode httpMode, String connectionId) {
        pause.accept(queueWait);
        return super.sendRequest(request, httpMode, connectionId);
    }

    @Override
    public HttpRequestResponse sendRequest(HttpRequest request, RequestOptions requestOptions) {
        pause.accept(queueWait);
        return super.sendRequest(request, requestOptions);
    }

    @Override
    protected HttpRequest outgoing(HttpRequest request) {
        return request;
    }

    private static void sleep(Duration wait) {
        try {
            Thread.sleep(wait.toMillis());
        } catch (InterruptedException interrupted) {
            Thread.currentThread().interrupt();
            throw new IllegalStateException("interrupted while queued", interrupted);
        }
    }
}
