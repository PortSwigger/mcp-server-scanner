package com.mcpscanner.testutil;

import burp.api.montoya.http.HttpMode;
import burp.api.montoya.http.RedirectionMode;
import burp.api.montoya.http.RequestOptions;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;

import java.util.function.UnaryOperator;

public final class HandlerRoutedBurpHttp extends SendOnlyBurpHttp {

    private final UnaryOperator<HttpRequest> handlerRoute;
    private final SendOnlyBurpHttp network;

    public HandlerRoutedBurpHttp(UnaryOperator<HttpRequest> handlerRoute, SendOnlyBurpHttp network) {
        this.handlerRoute = handlerRoute;
        this.network = network;
    }

    @Override
    public HttpRequestResponse sendRequest(HttpRequest request) {
        return sendRequest(request, RequestOptions.requestOptions().withRedirectionMode(RedirectionMode.NEVER));
    }

    @Override
    public HttpRequestResponse sendRequest(HttpRequest request, HttpMode httpMode, String connectionId) {
        return sendRequest(request, RequestOptions.requestOptions().withRedirectionMode(RedirectionMode.NEVER)
                .withHttpMode(httpMode).withConnectionId(connectionId));
    }

    @Override
    public HttpRequestResponse sendRequest(HttpRequest request, RequestOptions requestOptions) {
        return HttpRequestResponse.httpRequestResponse(request,
                network.sendRequest(handlerRoute.apply(request), requestOptions).response());
    }
}
