package com.mcpscanner.proxy;

import com.mcpscanner.client.RedirectLoggingInterceptor;
import com.mcpscanner.http.evidence.WireRecord;

import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpHeaders;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;

final class SseMessagePoster {

    private final HttpClient httpClient;
    private final RedirectLoggingInterceptor redirectInterceptor;
    private final Duration responseTimeout;
    private final SessionLifecycle lifecycle;
    private final Map<Thread, AtomicBoolean> activePosts = new LinkedHashMap<>();

    SseMessagePoster(HttpClient httpClient, RedirectLoggingInterceptor redirectInterceptor, Duration responseTimeout,
                     SessionLifecycle lifecycle) {
        this.httpClient = httpClient;
        this.redirectInterceptor = redirectInterceptor;
        this.responseTimeout = responseTimeout;
        this.lifecycle = lifecycle;
    }

    MessagePostResult post(String messageEndpoint, String jsonBody, Map<String, String> requestHeaders)
            throws IOException, InterruptedException {
        HttpRequest request = messagePost(messageEndpoint, jsonBody, requestHeaders);
        Thread caller = Thread.currentThread();
        AtomicBoolean timedOut = track(caller);
        CompletableFuture.delayedExecutor(responseTimeout.toNanos(), TimeUnit.NANOSECONDS)
                .execute(() -> expire(caller, timedOut));
        try {
            return send(request, jsonBody);
        } catch (InterruptedException e) {
            if (timedOut.get()) {
                throw new IOException("Timed out waiting for SSE message POST response", e);
            }
            throw e;
        } finally {
            untrack(caller, timedOut);
        }
    }

    synchronized void interruptOtherPosts() {
        Thread current = Thread.currentThread();
        activePosts.keySet().stream().filter(thread -> thread != current).forEach(Thread::interrupt);
    }

    private HttpRequest messagePost(String messageEndpoint, String jsonBody, Map<String, String> requestHeaders) {
        HttpRequest.Builder builder = HttpRequest.newBuilder()
                .uri(URI.create(messageEndpoint))
                .timeout(responseTimeout)
                .header("Content-Type", "application/json")
                .POST(HttpRequest.BodyPublishers.ofString(jsonBody));
        SseRequestHeaders.forwardable(requestHeaders).forEach(builder::header);
        return builder.build();
    }

    private MessagePostResult send(HttpRequest request, String jsonBody) throws IOException, InterruptedException {
        RecordedPostBodies bodies = new RecordedPostBodies();
        HttpResponse<String> response = redirectInterceptor.sendAndLog(httpClient, request, bodies);
        int status = response.statusCode();
        return new MessagePostResult(status, response.body(), RelayedHeaders.ofMultiValued(headersOf(response)),
                recorded(request, jsonBody, response, bodies.lastReceived()));
    }

    private static RecordedExchange recorded(HttpRequest request, String jsonBody, HttpResponse<String> response,
                                             byte[] received) {
        HttpRequest finalHop = response.request() == null ? request : response.request();
        WireRecord head = WireRecord.ofJdk(finalHop, bodySentBy(finalHop, jsonBody), response);
        return new RecordedExchange(jsonBody, head.withBody(received, false));
    }

    private static byte[] bodySentBy(HttpRequest hop, String jsonBody) {
        return "POST".equals(hop.method()) ? jsonBody.getBytes(StandardCharsets.UTF_8) : new byte[0];
    }

    private static Map<String, List<String>> headersOf(HttpResponse<String> response) {
        HttpHeaders headers = response.headers();
        return headers == null ? Map.of() : headers.map();
    }

    private synchronized AtomicBoolean track(Thread caller) throws IOException {
        if (!lifecycle.isOpen()) {
            throw new IOException("Session closed");
        }
        AtomicBoolean timedOut = new AtomicBoolean();
        activePosts.put(caller, timedOut);
        return timedOut;
    }

    private synchronized void untrack(Thread caller, AtomicBoolean timedOut) {
        activePosts.remove(caller);
        if (timedOut.get()) {
            Thread.interrupted();
        }
    }

    private synchronized void expire(Thread caller, AtomicBoolean timedOut) {
        if (activePosts.get(caller) == timedOut) {
            timedOut.set(true);
            caller.interrupt();
        }
    }
}
