package com.mcpscanner.mcp;

import java.io.BufferedReader;
import java.io.FilterInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.Locale;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;

public final class StreamingResponseReader {

    private final Duration responseTimeout;

    public StreamingResponseReader(Duration responseTimeout) {
        this.responseTimeout = responseTimeout;
    }

    public UnstreamedReply read(int status, String contentType, InputStream body, String requestBody,
                       ServerPingAnswerer serverRequests) throws IOException {
        String reply = withinDeadline(body, bounded -> replyBody(contentType, bounded, requestBody, serverRequests));
        return new UnstreamedReply(status, isEventStream(contentType) ? "application/json" : contentType, reply);
    }

    public void awaitReply(String contentType, InputStream body, String requestBody) throws IOException {
        withinDeadline(body, bounded -> replyBody(contentType, bounded, requestBody, ServerPingAnswerer.ignoring()));
    }

    private String withinDeadline(InputStream body, BodyRead read) throws IOException {
        ScheduledExecutorService deadline = Executors.newSingleThreadScheduledExecutor(StreamingResponseReader::daemon);
        AtomicBoolean timedOut = new AtomicBoolean();
        var timeout = deadline.schedule(() -> expire(body, timedOut), responseTimeout.toNanos(), TimeUnit.NANOSECONDS);
        try {
            String reply = read.from(new BoundedResponseStream(body));
            if (timedOut.get()) throw new IOException("HTTP response read timed out");
            return reply;
        } finally {
            timeout.cancel(false);
            deadline.shutdownNow();
        }
    }

    private static String replyBody(String contentType, InputStream body, String requestBody,
                                    ServerPingAnswerer serverRequests) throws IOException {
        if (!isEventStream(contentType)) {
            return BoundedBodyReader.readUtf8(body);
        }
        var reader = new BufferedReader(new InputStreamReader(body, StandardCharsets.UTF_8));
        String reply = SseResponseParser.extractJsonRpcResponse(reader, SseResponseParser.expectedReplyId(requestBody),
                serverRequests);
        return reply == null ? "" : reply;
    }

    private static boolean isEventStream(String contentType) {
        return contentType != null && contentType.toLowerCase(Locale.ROOT).contains("text/event-stream");
    }

    private static void expire(InputStream body, AtomicBoolean timedOut) {
        timedOut.set(true);
        try {
            body.close();
        } catch (IOException ignored) {
        }
    }

    private static Thread daemon(Runnable task) {
        Thread thread = new Thread(task, "mcp-http-response-deadline");
        thread.setDaemon(true);
        return thread;
    }

    private interface BodyRead {
        String from(InputStream body) throws IOException;
    }

    private static final class BoundedResponseStream extends FilterInputStream {
        private int consumed;

        private BoundedResponseStream(InputStream stream) {
            super(stream);
        }

        @Override
        public int read() throws IOException {
            int value = in.read();
            if (value != -1) record(1);
            return value;
        }

        @Override
        public int read(byte[] bytes, int offset, int length) throws IOException {
            int count = in.read(bytes, offset, Math.min(length, BoundedBodyReader.MAX_RESPONSE_BYTES - consumed + 1));
            if (count > 0) record(count);
            return count;
        }

        private void record(int count) throws IOException {
            consumed += count;
            if (consumed > BoundedBodyReader.MAX_RESPONSE_BYTES) throw new IOException("HTTP response exceeded byte limit");
        }
    }
}
