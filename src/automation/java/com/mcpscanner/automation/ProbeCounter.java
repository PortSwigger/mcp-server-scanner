package com.mcpscanner.automation;

import burp.api.montoya.http.Http;
import burp.api.montoya.http.message.HttpRequestResponse;
import com.mcpscanner.http.CountingHttp;
import com.mcpscanner.http.ExchangeCounter;
import com.mcpscanner.mcp.TooManyRequests;
import com.mcpscanner.proxy.ProxyFabricatedReply;

import java.util.concurrent.atomic.AtomicInteger;
import java.util.function.Predicate;

public final class ProbeCounter implements ExchangeCounter {


    private final Predicate<HttpRequestResponse> reachedTarget;
    private final AtomicInteger sent = new AtomicInteger();
    private final AtomicInteger reached = new AtomicInteger();

    public ProbeCounter(Predicate<HttpRequestResponse> reachedTarget) {
        this.reachedTarget = reachedTarget;
    }

    public static ProbeCounter throughTheExtensionProxy() {
        return new ProbeCounter(ProbeCounter::answeredByTheTarget);
    }

    public Http wrap(Http http) {
        return CountingHttp.counting(http, this);
    }

    public Http wrapMarking(Http http) {
        return CountingHttp.marking(http, this, CheckProbeMarker::marked);
    }

    public int sent() {
        return sent.get();
    }

    public int reached() {
        return reached.get();
    }

    void reset() {
        sent.set(0);
        reached.set(0);
    }

    @Override
    public HttpRequestResponse counted(HttpRequestResponse exchange) {
        sent.incrementAndGet();
        if (reachedTarget.test(exchange)) {
            reached.incrementAndGet();
        }
        return exchange;
    }

    private static boolean answeredByTheTarget(HttpRequestResponse exchange) {
        return exchange != null && exchange.response() != null
                && !TooManyRequests.answered(exchange)
                && !ProxyFabricatedReply.matches(exchange.response())
                && !SinkReply.matches(exchange.response());
    }
}
