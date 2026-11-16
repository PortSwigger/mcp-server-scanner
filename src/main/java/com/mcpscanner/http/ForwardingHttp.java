package com.mcpscanner.http;

import burp.api.montoya.core.Registration;
import burp.api.montoya.http.Http;
import burp.api.montoya.http.HttpMode;
import burp.api.montoya.http.RequestOptions;
import burp.api.montoya.http.execution.RequestEngineOptions;
import burp.api.montoya.http.execution.RequestExecutionEngine;
import burp.api.montoya.http.handler.HttpHandler;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.analysis.ResponseKeywordsAnalyzer;
import burp.api.montoya.http.message.responses.analysis.ResponseVariationsAnalyzer;
import burp.api.montoya.http.sessions.CookieJar;
import burp.api.montoya.http.sessions.SessionHandlingAction;

import java.util.List;
import java.util.Objects;

public abstract class ForwardingHttp implements Http, OutsideBurpSends {

    private final Http delegate;

    protected ForwardingHttp(Http delegate) {
        this.delegate = Objects.requireNonNull(delegate);
    }

    protected abstract HttpRequest outgoing(HttpRequest request);

    protected final Http delegate() {
        return delegate;
    }

    protected HttpRequestResponse incoming(HttpRequestResponse exchange) {
        return exchange;
    }

    @Override
    public void sentOutsideBurp(HttpRequestResponse exchange) {
        OutsideBurpSends.report(delegate, exchange);
    }

    @Override
    public void streamRefused() {
        OutsideBurpSends.reportRefusal(delegate);
    }

    @Override
    public HttpRequestResponse sendRequest(HttpRequest request) {
        return incoming(delegate.sendRequest(outgoing(request)));
    }

    @Override
    public HttpRequestResponse sendRequest(HttpRequest request, HttpMode httpMode) {
        return incoming(delegate.sendRequest(outgoing(request), httpMode));
    }

    @Override
    public HttpRequestResponse sendRequest(HttpRequest request, HttpMode httpMode, String connectionId) {
        return incoming(delegate.sendRequest(outgoing(request), httpMode, connectionId));
    }

    @Override
    public HttpRequestResponse sendRequest(HttpRequest request, RequestOptions requestOptions) {
        return incoming(delegate.sendRequest(outgoing(request), requestOptions));
    }

    @Override
    public List<HttpRequestResponse> sendRequests(List<HttpRequest> requests) {
        return incoming(delegate.sendRequests(outgoing(requests)));
    }

    @Override
    public List<HttpRequestResponse> sendRequests(List<HttpRequest> requests, HttpMode httpMode) {
        return incoming(delegate.sendRequests(outgoing(requests), httpMode));
    }

    @Override
    public Registration registerHttpHandler(HttpHandler handler) {
        return delegate.registerHttpHandler(handler);
    }

    @Override
    public Registration registerSessionHandlingAction(SessionHandlingAction sessionHandlingAction) {
        return delegate.registerSessionHandlingAction(sessionHandlingAction);
    }

    @Override
    public RequestExecutionEngine createRequestEngine() {
        return delegate.createRequestEngine();
    }

    @Override
    public RequestExecutionEngine createRequestEngine(RequestEngineOptions options) {
        return delegate.createRequestEngine(options);
    }

    @Override
    public ResponseKeywordsAnalyzer createResponseKeywordsAnalyzer(List<String> keywords) {
        return delegate.createResponseKeywordsAnalyzer(keywords);
    }

    @Override
    public ResponseVariationsAnalyzer createResponseVariationsAnalyzer() {
        return delegate.createResponseVariationsAnalyzer();
    }

    @Override
    public CookieJar cookieJar() {
        return delegate.cookieJar();
    }

    private List<HttpRequest> outgoing(List<HttpRequest> requests) {
        return requests.stream().map(this::outgoing).toList();
    }

    private List<HttpRequestResponse> incoming(List<HttpRequestResponse> exchanges) {
        return exchanges.stream().map(this::incoming).toList();
    }
}
