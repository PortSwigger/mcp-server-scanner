package com.mcpscanner.proxy;

import com.mcpscanner.logging.McpEventLog;
import com.mcpscanner.mcp.RawSseFrame;
import com.mcpscanner.mcp.SseFrame;
import com.mcpscanner.mcp.SseFrameReader;
import com.mcpscanner.mcp.SseResponseParser;

import java.io.BufferedInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.function.Predicate;

final class SseStreamReader {

    private static final String MESSAGE_EVENT = "message";

    private final String threadName;
    private final SseReplyDispatcher replies;
    private final McpEventLog eventLog;
    private final SessionLifecycle lifecycle;
    private final Predicate<String> serverRequests;
    private InputStream stream;
    private InputStream buffered;
    private SseFrameReader endpointFrames;
    private Thread thread;
    private volatile boolean running;

    SseStreamReader(String threadName, SseReplyDispatcher replies, McpEventLog eventLog, SessionLifecycle lifecycle,
                    Predicate<String> serverRequests) {
        this.threadName = threadName;
        this.replies = replies;
        this.eventLog = eventLog;
        this.lifecycle = lifecycle;
        this.serverRequests = serverRequests;
    }

    synchronized SseFrameReader adopt(InputStream body) throws IOException {
        if (!lifecycle.isOpen()) {
            body.close();
            throw new IOException("Session closed");
        }
        stream = body;
        buffered = new BufferedInputStream(body);
        endpointFrames = SseResponseParser.endpointFrames(buffered);
        return endpointFrames;
    }

    synchronized void start() throws IOException {
        if (!lifecycle.isOpen() || endpointFrames == null) {
            throw new IOException("Session closed");
        }
        replies.reopen();
        running = true;
        SseFrameReader source = SseResponseParser.eventFrames(endpointFrames.remainder(buffered));
        thread = new Thread(() -> readLoop(source), threadName);
        thread.setDaemon(true);
        thread.start();
    }

    boolean isRunning() {
        return running;
    }

    void markStopped() {
        running = false;
    }

    synchronized void halt() {
        running = false;
        closeStream();
    }

    synchronized Thread stop() {
        halt();
        Thread stopped = thread;
        if (stopped != null) {
            stopped.interrupt();
        }
        thread = null;
        buffered = null;
        endpointFrames = null;
        return stopped;
    }

    private void readLoop(SseFrameReader source) {
        try {
            while (running) {
                RawSseFrame frame = SseResponseParser.nextDataFrame(source);
                if (frame == null) {
                    exit(new IOException("SSE stream closed"));
                    return;
                }
                dispatch(frame);
            }
        } catch (Throwable e) {
            exit(e);
        }
    }

    private void dispatch(RawSseFrame frame) {
        SseFrame event = SseFrame.parse(frame.text());
        if (MESSAGE_EVENT.equals(event.eventType()) && !serverRequests.test(event.data())) {
            replies.dispatch(new StreamedReply(event.data(), frame.bytes()));
        }
    }

    private void exit(Throwable cause) {
        boolean requested = !running;
        running = false;
        int failed = replies.terminate(cause);
        String message = "SSE reader thread exited: " + cause.getMessage() + " (failed-waiters=" + failed + ")";
        if (requested && failed == 0) {
            eventLog.debug(message);
        } else {
            eventLog.warn(message);
        }
    }

    private void closeStream() {
        if (stream != null) {
            try {
                stream.close();
            } catch (IOException ignored) {
            }
            stream = null;
        }
    }
}
