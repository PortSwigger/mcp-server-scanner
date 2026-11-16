package com.mcpscanner.automation;

import burp.api.montoya.core.ToolType;
import burp.api.montoya.http.HttpService;
import burp.api.montoya.http.handler.HttpHandler;
import burp.api.montoya.http.handler.HttpRequestToBeSent;
import burp.api.montoya.http.handler.HttpResponseReceived;
import burp.api.montoya.http.handler.RequestToBeSentAction;
import burp.api.montoya.http.handler.ResponseReceivedAction;

import java.util.concurrent.atomic.AtomicInteger;
import java.util.function.Supplier;

public final class BuiltInTrafficSink implements HttpHandler {

    private final BaseRequestLedger launchedRequests;
    private final Supplier<HttpService> sinkService;
    private final AtomicInteger diverted = new AtomicInteger();
    private volatile boolean active;

    public BuiltInTrafficSink(BaseRequestLedger launchedRequests, Supplier<HttpService> sinkService) {
        this.launchedRequests = launchedRequests;
        this.sinkService = sinkService;
    }

    @Override
    public RequestToBeSentAction handleHttpRequestToBeSent(HttpRequestToBeSent request) {
        if (CheckProbeMarker.carries(request)) {
            return RequestToBeSentAction.continueWith(CheckProbeMarker.stripped(request));
        }
        if (!divertible(request)) {
            return RequestToBeSentAction.continueWith(request);
        }
        diverted.incrementAndGet();
        return RequestToBeSentAction.continueWith(request.withService(sinkService.get()));
    }

    @Override
    public ResponseReceivedAction handleHttpResponseReceived(HttpResponseReceived response) {
        return ResponseReceivedAction.continueWith(response);
    }

    public void reset(boolean divertBuiltInChecks) {
        active = divertBuiltInChecks;
        diverted.set(0);
        launchedRequests.clear();
    }

    public int diverted() {
        return diverted.get();
    }

    private boolean divertible(HttpRequestToBeSent request) {
        return active
                && request.toolSource().isFromTool(ToolType.SCANNER)
                && !launchedRequests.contains(request);
    }
}
