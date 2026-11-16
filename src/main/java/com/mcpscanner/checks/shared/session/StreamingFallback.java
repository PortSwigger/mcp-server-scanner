package com.mcpscanner.checks.shared.session;

import burp.api.montoya.http.Http;
import burp.api.montoya.http.RequestOptions;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import com.mcpscanner.http.OutsideBurpSends;
import com.mcpscanner.mcp.BurpStreamingRefusal;

import java.time.Duration;
import java.util.Optional;
import java.util.function.Supplier;

public final class StreamingFallback {

    private static final Duration DEFAULT_RESPONSE_TIMEOUT = Duration.ofSeconds(30);

    private final OutsideBurpClient unstreamingClient;
    private final OutsideBurpClient foreignHostClient;
    private final StreamingRoutes streamingRoutes = new StreamingRoutes();

    StreamingFallback(OutsideBurpClient unstreamingClient, OutsideBurpClient foreignHostClient) {
        this.unstreamingClient = unstreamingClient;
        this.foreignHostClient = foreignHostClient;
    }

    public static StreamingFallback outsideBurp() {
        return outsideBurp(DEFAULT_RESPONSE_TIMEOUT);
    }

    static StreamingFallback outsideBurp(Duration responseTimeout) {
        return new StreamingFallback(new UnstreamingProbeClient(responseTimeout),
                new RawSocketProbeClient(responseTimeout));
    }

    public Http around(Http http) {
        return new StreamRecoveringHttp(http, this);
    }

    public boolean sendsOutsideBurp(HttpRequest probe) {
        return streamingRoutes.bypassBurp(probe);
    }

    public void forgetStreamedRoutes() {
        streamingRoutes.forget();
    }

    HttpRequestResponse send(Http http, HttpRequest probe, RequestOptions options) {
        return send(http, probe, () -> http.sendRequest(probe, options));
    }

    HttpRequestResponse send(Http http, HttpRequest probe, Supplier<HttpRequestResponse> throughBurp) {
        if (sendsOutsideBurp(probe)) {
            return refusedByBurp(http, probe);
        }
        try {
            return throughBurp.get();
        } catch (RuntimeException failure) {
            if (!BurpStreamingRefusal.refused(failure)) {
                throw failure;
            }
            streamingRoutes.streamed(probe);
            return refusedByBurp(http, probe);
        }
    }

    private HttpRequestResponse refusedByBurp(Http http, HttpRequest probe) {
        OutsideBurpSends.reportRefusal(http);
        return outsideBurp(http, probe);
    }

    private HttpRequestResponse outsideBurp(Http http, HttpRequest probe) {
        Optional<HttpRequestResponse> sent = clientFor(probe).send(ScannerSentinelRemoval.from(probe));
        sent.ifPresent(exchange -> OutsideBurpSends.report(http, exchange));
        return sent.orElseGet(() -> HttpRequestResponse.httpRequestResponse(probe, null));
    }

    private OutsideBurpClient clientFor(HttpRequest probe) {
        return HostHeaderFidelity.keptOutsideBurp(probe) ? unstreamingClient : foreignHostClient;
    }
}
