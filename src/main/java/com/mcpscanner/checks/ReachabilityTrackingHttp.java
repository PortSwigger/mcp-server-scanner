package com.mcpscanner.checks;

import burp.api.montoya.core.Registration;
import burp.api.montoya.http.Http;
import burp.api.montoya.http.HttpMode;
import burp.api.montoya.http.RequestOptions;
import burp.api.montoya.http.handler.HttpHandler;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.analysis.ResponseKeywordsAnalyzer;
import burp.api.montoya.http.message.responses.analysis.ResponseVariationsAnalyzer;
import burp.api.montoya.http.sessions.CookieJar;
import burp.api.montoya.http.sessions.SessionHandlingAction;

import java.util.List;

/**
 * Wraps {@link Http} and records whether any request reached the server (returned a non-null
 * HTTP response). Self-discovering per-host checks use this to tell a transient HTTP-layer
 * failure (no probe ever got a response) apart from a clean negative (the server answered, just
 * nothing vulnerable): the former must release the {@link HostDedup} claim so a later insertion
 * point retries, the latter must keep it so the battery does not re-run ~29 times per scan.
 */
final class ReachabilityTrackingHttp implements Http {

    private final Http delegate;
    private volatile boolean reachedServer;

    ReachabilityTrackingHttp(Http delegate) {
        this.delegate = delegate;
    }

    boolean reachedServer() {
        return reachedServer;
    }

    private HttpRequestResponse track(HttpRequestResponse response) {
        if (response != null && response.response() != null) {
            reachedServer = true;
        }
        return response;
    }

    @Override
    public HttpRequestResponse sendRequest(HttpRequest request) {
        return track(delegate.sendRequest(request));
    }

    @Override
    public HttpRequestResponse sendRequest(HttpRequest request, HttpMode httpMode) {
        return track(delegate.sendRequest(request, httpMode));
    }

    @Override
    public HttpRequestResponse sendRequest(HttpRequest request, HttpMode httpMode, String connectionId) {
        return track(delegate.sendRequest(request, httpMode, connectionId));
    }

    @Override
    public HttpRequestResponse sendRequest(HttpRequest request, RequestOptions requestOptions) {
        return track(delegate.sendRequest(request, requestOptions));
    }

    @Override
    public List<HttpRequestResponse> sendRequests(List<HttpRequest> requests) {
        List<HttpRequestResponse> responses = delegate.sendRequests(requests);
        responses.forEach(this::track);
        return responses;
    }

    @Override
    public List<HttpRequestResponse> sendRequests(List<HttpRequest> requests, HttpMode httpMode) {
        List<HttpRequestResponse> responses = delegate.sendRequests(requests, httpMode);
        responses.forEach(this::track);
        return responses;
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
}
