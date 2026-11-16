package com.mcpscanner.client;

import burp.api.montoya.http.Http;
import burp.api.montoya.http.RedirectionMode;
import burp.api.montoya.http.RequestOptions;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import com.mcpscanner.http.BurpMessages;
import com.mcpscanner.http.EmptyResponse;
import com.mcpscanner.mcp.BurpStreamingRefusal;
import com.mcpscanner.mcp.BoundedBodyReader;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.time.Duration;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.RejectedExecutionException;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.function.LongSupplier;

public final class BurpProtocolHttpTransport implements ProtocolHttpTransport, AutoCloseable {

    private final Http http;
    private final BurpMessages messages;
    private final LongSupplier nanoClock;
    private final AtomicInteger senderCount = new AtomicInteger();
    private final ExecutorService burpSenders = Executors.newCachedThreadPool(this::burpSenderThread);

    public BurpProtocolHttpTransport(Http http) {
        this(http, new BurpMessages());
    }

    BurpProtocolHttpTransport(Http http, BurpMessages messages) {
        this(http, messages, System::nanoTime);
    }

    BurpProtocolHttpTransport(Http http, BurpMessages messages, LongSupplier nanoClock) {
        this.http = http;
        this.messages = messages;
        this.nanoClock = nanoClock;
    }

    @Override
    public ProtocolHttpResponse send(ProtocolHttpRequest request, Duration timeout)
            throws IOException, InterruptedException {
        try {
            return sendAndRead(request, timeout);
        } catch (RuntimeException failure) {
            if (BurpStreamingRefusal.refused(failure)) {
                throw new BurpStreamingResponseException(request.uri());
            }
            throw failure;
        }
    }

    private ProtocolHttpResponse sendAndRead(ProtocolHttpRequest request, Duration timeout)
            throws IOException, InterruptedException {
        long started = nanoClock.getAsLong();
        HttpRequestResponse sent = awaitBurp(sendThroughBurp(toBurpRequest(request), optionsFor(timeout)));
        if (sent == null || sent.response() == null) throw noResponse(request, timeout);
        if (EmptyResponse.is(sent.response())) throw emptyReply(request, timeout, started);
        return toResponse(sent.response(), request);
    }

    @Override
    public void close() {
        burpSenders.shutdownNow();
    }

    private Future<HttpRequestResponse> sendThroughBurp(HttpRequest burpRequest, RequestOptions options) {
        try {
            return burpSenders.submit(() -> http.sendRequest(burpRequest, options));
        } catch (RejectedExecutionException closed) {
            throw new IllegalStateException("Burp transport is closed: the extension is unloading", closed);
        }
    }

    private static HttpRequestResponse awaitBurp(Future<HttpRequestResponse> pending)
            throws IOException, InterruptedException {
        try {
            return pending.get();
        } catch (InterruptedException interrupted) {
            pending.cancel(true);
            throw interrupted;
        } catch (ExecutionException failed) {
            throw rethrown(failed.getCause());
        }
    }

    private static IOException rethrown(Throwable cause) {
        if (cause instanceof RuntimeException runtime) throw runtime;
        if (cause instanceof Error error) throw error;
        return cause instanceof IOException io ? io : new IOException(cause);
    }

    private Thread burpSenderThread(Runnable task) {
        Thread thread = new Thread(task, "mcp-burp-http-" + senderCount.incrementAndGet());
        thread.setDaemon(true);
        return thread;
    }

    private HttpRequest toBurpRequest(ProtocolHttpRequest request) {
        return messages.toRequest(request.uri().toString(), request.method(),
                BurpMessages.multiValued(request.headers()), request.body());
    }

    private static RequestOptions optionsFor(Duration timeout) {
        return RequestOptions.requestOptions()
                .withRedirectionMode(RedirectionMode.NEVER)
                .withResponseTimeout(timeout.toMillis());
    }

    private static ProtocolHttpResponse toResponse(HttpResponse response, ProtocolHttpRequest request)
            throws IOException {
        return new ProtocolHttpResponse(response.statusCode(), BurpMessages.groupedHeaders(response),
                new ByteArrayInputStream(unframedBody(response)), request.uri());
    }

    private static byte[] unframedBody(HttpResponse response) throws IOException {
        if (!BurpMessages.bodyWithin(response, BoundedBodyReader.MAX_RESPONSE_BYTES)) {
            throw BoundedBodyReader.oversizedResponse();
        }
        return BurpMessages.unframedBody(response);
    }

    private IOException emptyReply(ProtocolHttpRequest request, Duration timeout, long started) {
        boolean timedOut = nanoClock.getAsLong() - started >= timeout.toNanos();
        return timedOut ? noResponse(request, timeout) : new ConnectionClosedBeforeReplyException(request.uri());
    }

    private static IOException noResponse(ProtocolHttpRequest request, Duration timeout) {
        return new BurpNoResponseException("No response from " + request.uri() + " through Burp: the connection or TLS handshake"
                + " failed, or no complete reply arrived within " + readable(timeout)
                + " (for example, the server kept its reply stream open after answering)."
                + " If the server waits for a ping answer before replying, turn off \"" + BurpNetworkingSetting.NAME
                + "\"."
                + " Burp's Event log has the cause");
    }

    private static String readable(Duration timeout) {
        return timeout.toMillisPart() == 0 && !timeout.isZero()
                ? timeout.toSeconds() + " s"
                : timeout.toMillis() + " ms";
    }
}
