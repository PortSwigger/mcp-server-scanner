package com.mcpscanner.client;

import com.mcpscanner.mcp.BoundedBodyReader;
import com.mcpscanner.mcp.RawSseFrame;
import com.mcpscanner.mcp.SseFrameReader;

import java.io.BufferedInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.time.Duration;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.Future;
import java.util.concurrent.ThreadPoolExecutor;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;

final class SseReplyReader implements AutoCloseable {
    private static final SseFrameReader.Limits EVENT_LIMITS = SseFrameReader.Limits.perFrame(
            BoundedBodyReader.MAX_RESPONSE_BYTES, "SSE event exceeded response bound");
    private final InputStream stream;
    private final SseFrameReader frames;
    private final ThreadPoolExecutor executor;
    private final Duration timeout;
    private long deadline;

    SseReplyReader(InputStream stream, ThreadPoolExecutor executor, Duration timeout) {
        this.stream = stream;
        this.frames = SseFrameReader.capturing(new BufferedInputStream(stream), EVENT_LIMITS);
        this.executor = executor;
        this.timeout = timeout;
        beginReplyWait();
    }

    void beginReplyWait() {
        deadline = System.nanoTime() + timeout.toNanos();
    }

    String nextEvent() {
        RawSseFrame frame = nextFrame();
        return frame == null ? null : frame.text();
    }

    RawSseFrame nextFrame() {
        Future<RawSseFrame> read = executor.submit(this::readFrame);
        try {
            return read.get(Math.max(0, deadline - System.nanoTime()), TimeUnit.NANOSECONDS);
        } catch (TimeoutException failure) {
            close();
            throw new IllegalStateException("SSE reply wait timed out", failure);
        } catch (InterruptedException failure) {
            close();
            Thread.currentThread().interrupt();
            throw new IllegalStateException("SSE reply wait interrupted", failure);
        } catch (ExecutionException failure) {
            close();
            throw new IllegalStateException("SSE stream failed", failure.getCause());
        } finally {
            read.cancel(true);
            executor.remove((Runnable) read);
        }
    }

    private RawSseFrame readFrame() throws IOException {
        return frames.nextRawFrame();
    }

    @Override
    public void close() {
        try {
            stream.close();
        } catch (IOException ignored) {
        }
    }
}
