package com.mcpscanner.auth.oauth;

import fi.iki.elonen.NanoHTTPD;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.Map;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;

public final class CallbackListener implements AutoCloseable {

    static final String LOOPBACK_HOST = "127.0.0.1";
    private static final int SOCKET_READ_TIMEOUT_MS = 30_000;
    private static final Duration CALLBACK_ANSWER_GRACE = Duration.ofSeconds(2);

    private static final String SUCCESS_PAGE = "<!doctype html><html><body>"
            + "<h2>Authorization complete</h2>"
            + "<p>You can close this window now.</p>"
            + "</body></html>";

    private static final String FAILURE_PAGE = "<!doctype html><html><body>"
            + "<h2>Authorization failed</h2>"
            + "<p>Return to the extension for details.</p>"
            + "</body></html>";

    private static final String HTML = "text/html; charset=utf-8";

    private static final String GONE_BODY = "<!doctype html><html><body>"
            + "<h2>Already handled</h2>"
            + "<p>This authorization callback has already been processed.</p>"
            + "</body></html>";

    private final CallbackHttpServer server;
    private final CompletableFuture<CallbackResult> future = new CompletableFuture<>();
    private final AtomicBoolean closed = new AtomicBoolean(false);
    private final AtomicBoolean callbackServed = new AtomicBoolean(false);
    private final CountDownLatch callbackAnswered = new CountDownLatch(1);

    private CallbackListener(String host, int port, String path) {
        this.server = new CallbackHttpServer(withoutBrackets(host), port, path);
    }

    public static CallbackListener start(int port, String path) throws IOException {
        return start(LOOPBACK_HOST, port, path);
    }

    public static CallbackListener start(String host, int port, String path) throws IOException {
        CallbackListener listener = new CallbackListener(host, port, path);
        listener.server.start(SOCKET_READ_TIMEOUT_MS, true);
        return listener;
    }

    public boolean isClosed() {
        return closed.get();
    }

    public int port() {
        return server.getListeningPort();
    }

    public CompletableFuture<CallbackResult> awaitCallback() {
        return future;
    }

    @Override
    public synchronized void close() {
        if (!closed.compareAndSet(false, true)) {
            return;
        }
        awaitInFlightCallbackAnswer();
        stopServerKeepingInterrupt();
        future.completeExceptionally(new OAuthException("Callback listener closed"));
    }

    private void awaitInFlightCallbackAnswer() {
        if (!callbackServed.get()) {
            return;
        }
        try {
            callbackAnswered.await(CALLBACK_ANSWER_GRACE.toMillis(), TimeUnit.MILLISECONDS);
        } catch (InterruptedException interrupted) {
            Thread.currentThread().interrupt();
        }
    }

    private void stopServerKeepingInterrupt() {
        boolean interrupted = Thread.interrupted();
        try {
            server.stop();
        } finally {
            if (interrupted) {
                Thread.currentThread().interrupt();
            }
        }
    }

    private NanoHTTPD.Response handleCallback(Map<String, String> params) {
        if (!callbackServed.compareAndSet(false, true)) {
            return NanoHTTPD.newFixedLengthResponse(
                    NanoHTTPD.Response.Status.GONE, HTML, GONE_BODY);
        }
        String error = params.get("error");
        CallbackResult result = new CallbackResult(
                params.get("code"), params.get("state"),
                sanitizeForLog(error),
                sanitizeForLog(params.get("error_description")), params.get("iss"));
        future.complete(result);
        return error == null
                ? closingAfterSent(NanoHTTPD.Response.Status.OK, SUCCESS_PAGE)
                : closingAfterSent(NanoHTTPD.Response.Status.BAD_REQUEST, FAILURE_PAGE);
    }

    private NanoHTTPD.Response closingAfterSent(NanoHTTPD.Response.Status status, String page) {
        byte[] body = page.getBytes(StandardCharsets.UTF_8);
        return new NanoHTTPD.Response(status, HTML, new ByteArrayInputStream(body), body.length) {
            @Override
            public void close() throws IOException {
                super.close();
                callbackAnswered.countDown();
                CallbackListener.this.close();
            }
        };
    }

    private static String withoutBrackets(String host) {
        return host.startsWith("[") && host.endsWith("]") ? host.substring(1, host.length() - 1) : host;
    }

    static String sanitizeForLog(String value) {
        if (value == null) {
            return null;
        }
        return value.replaceAll("[\r\n\t]", " ");
    }

    private final class CallbackHttpServer extends NanoHTTPD {

        private final String callbackPath;

        private CallbackHttpServer(String host, int port, String path) {
            super(host, port);
            this.callbackPath = path;
        }

        @Override
        public Response serve(IHTTPSession session) {
            if (!callbackPath.equals(session.getUri())) {
                return newFixedLengthResponse(
                        Response.Status.NOT_FOUND, "text/plain; charset=utf-8", "Not found");
            }
            return handleCallback(session.getParms());
        }
    }
}
