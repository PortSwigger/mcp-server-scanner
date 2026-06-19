package com.mcpscanner.auth.oauth;

import com.mcpscanner.logging.McpEventLog;
import fi.iki.elonen.NanoHTTPD;

import java.io.IOException;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicBoolean;

public final class CallbackListener implements AutoCloseable {

    private static final String LOOPBACK_HOST = "127.0.0.1";
    private static final int SOCKET_READ_TIMEOUT_MS = 30_000;

    private static final Set<CallbackListener> ACTIVE = ConcurrentHashMap.newKeySet();

    private static final String SUCCESS_PAGE = "<!doctype html><html><body>"
            + "<h2>Authorization complete</h2>"
            + "<p>You can close this window now.</p>"
            + "</body></html>";

    private static final String GONE_BODY = "<!doctype html><html><body>"
            + "<h2>Already handled</h2>"
            + "<p>This authorization callback has already been processed.</p>"
            + "</body></html>";

    private final CallbackHttpServer server;
    private final CompletableFuture<CallbackResult> future = new CompletableFuture<>();
    private final AtomicBoolean closed = new AtomicBoolean(false);
    private final AtomicBoolean callbackServed = new AtomicBoolean(false);

    private CallbackListener(int port, String path) {
        this.server = new CallbackHttpServer(port, path);
    }

    public static CallbackListener start(int port, String path) throws IOException {
        CallbackListener listener = new CallbackListener(port, path);
        ACTIVE.add(listener);
        try {
            listener.server.start(SOCKET_READ_TIMEOUT_MS, true);
        } catch (IOException | RuntimeException e) {
            ACTIVE.remove(listener);
            throw e;
        }
        if (listener.closed.get()) {
            listener.server.stop();
            ACTIVE.remove(listener);
            throw new IOException("Callback listener was cancelled during start");
        }
        return listener;
    }

    public static void closeAll() {
        closeAll(null);
    }

    public static void closeAll(McpEventLog eventLog) {
        McpEventLog log = eventLog != null ? eventLog : McpEventLog.noop();
        for (CallbackListener listener : List.copyOf(ACTIVE)) {
            try {
                listener.close();
            } catch (Exception e) {
                log.info("CallbackListener shutdown failed (ignored): " + e.getMessage());
            }
        }
    }

    public int port() {
        return server.getListeningPort();
    }

    public CompletableFuture<CallbackResult> awaitCallback() {
        return future;
    }

    @Override
    public void close() {
        if (!closed.compareAndSet(false, true)) {
            return;
        }
        ACTIVE.remove(this);
        server.stop();
        future.completeExceptionally(new OAuthException("Callback listener closed"));
    }

    private NanoHTTPD.Response handleCallback(Map<String, String> params) {
        if (!callbackServed.compareAndSet(false, true)) {
            return NanoHTTPD.newFixedLengthResponse(
                    NanoHTTPD.Response.Status.GONE, "text/html; charset=utf-8", GONE_BODY);
        }
        String error = params.get("error");
        CallbackResult result = new CallbackResult(
                params.get("code"), params.get("state"),
                sanitizeForLog(error),
                sanitizeForLog(params.get("error_description")));
        future.complete(result);
        scheduleStop();
        if (error == null) {
            return NanoHTTPD.newFixedLengthResponse(
                    NanoHTTPD.Response.Status.OK, "text/html; charset=utf-8", SUCCESS_PAGE);
        }
        return NanoHTTPD.newFixedLengthResponse(
                NanoHTTPD.Response.Status.BAD_REQUEST, "text/html; charset=utf-8", errorPage(result));
    }

    private void scheduleStop() {
        Thread stopThread = new Thread(() -> {
            // Yield briefly so the response is flushed before the socket closes.
            try { Thread.sleep(50); } catch (InterruptedException ignored) { Thread.currentThread().interrupt(); }
            close();
        }, "callback-listener-stop");
        stopThread.setDaemon(true);
        stopThread.start();
    }

    static String errorPage(CallbackResult result) {
        String error = escapeHtml(result.error());
        String description = result.errorDescription() != null
                ? ": " + escapeHtml(result.errorDescription())
                : "";
        return "<!doctype html><html><body><h2>Authorization failed</h2><p>"
                + error
                + description
                + "</p></body></html>";
    }

    static String sanitizeForLog(String value) {
        if (value == null) {
            return null;
        }
        return value.replaceAll("[\r\n\t]", " ");
    }

    private static String escapeHtml(String value) {
        if (value == null) {
            return "";
        }
        return value
                .replace("&", "&amp;")
                .replace("<", "&lt;")
                .replace(">", "&gt;")
                .replace("\"", "&quot;")
                .replace("'", "&#39;");
    }

    private final class CallbackHttpServer extends NanoHTTPD {

        private final String callbackPath;

        private CallbackHttpServer(int port, String path) {
            super(LOOPBACK_HOST, port);
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
