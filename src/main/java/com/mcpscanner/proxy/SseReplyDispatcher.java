package com.mcpscanner.proxy;

import com.fasterxml.jackson.databind.JsonNode;
import com.mcpscanner.logging.McpEventLog;
import com.mcpscanner.mcp.BoundedBodyReader;
import com.mcpscanner.mcp.McpObjectMapper;
import com.mcpscanner.core.protocol.McpResponses;

import java.io.IOException;
import java.time.Duration;
import java.util.List;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.LongSupplier;

final class SseReplyDispatcher {

    private final McpEventLog eventLog;
    private final LongSupplier pendingResponseBudget;
    private final Object dispatchLock = new Object();
    private final ConcurrentMap<String, CompletableFuture<StreamedReply>> waiters = new ConcurrentHashMap<>();
    private final PendingResponseBuffer pendingResponses = new PendingResponseBuffer();
    private final AtomicReference<Throwable> terminalFailure = new AtomicReference<>();

    SseReplyDispatcher(McpEventLog eventLog, LongSupplier pendingResponseBudget) {
        this.eventLog = eventLog;
        this.pendingResponseBudget = pendingResponseBudget;
    }

    CompletableFuture<StreamedReply> expect(String id) {
        CompletableFuture<StreamedReply> reply = new CompletableFuture<>();
        synchronized (dispatchLock) {
            StreamedReply buffered = pendingResponses.remove(id);
            if (buffered != null) {
                reply.complete(buffered);
            } else {
                waiters.put(id, reply);
            }
        }
        return reply;
    }

    StreamedReply await(CompletableFuture<StreamedReply> reply, Duration timeout)
            throws InterruptedException, ExecutionException, TimeoutException {
        Throwable terminal = terminalFailure.get();
        if (terminal != null && !reply.isDone()) {
            reply.completeExceptionally(terminal);
        }
        return reply.get(timeout.toMillis(), TimeUnit.MILLISECONDS);
    }

    void release(String id, CompletableFuture<StreamedReply> reply) {
        waiters.remove(id, reply);
    }

    void dispatch(StreamedReply reply) {
        String id = responseId(reply.json());
        if (id == null) {
            return;
        }
        synchronized (dispatchLock) {
            CompletableFuture<StreamedReply> waiter = waiters.remove(id);
            if (waiter != null) {
                waiter.complete(reply);
                return;
            }
            buffer(id, reply);
        }
    }

    int terminate(Throwable cause) {
        terminalFailure.compareAndSet(null, cause);
        return failAll(cause);
    }

    boolean isTerminated() {
        return terminalFailure.get() != null;
    }

    void reopen() {
        terminalFailure.set(null);
    }

    int failAll(Throwable cause) {
        int count = 0;
        for (String key : waiters.keySet()) {
            CompletableFuture<StreamedReply> waiter = waiters.remove(key);
            if (waiter != null) {
                waiter.completeExceptionally(cause);
                count++;
            }
        }
        return count;
    }

    void clearBuffered() {
        synchronized (dispatchLock) {
            pendingResponses.clear();
        }
    }

    int pendingRequests() {
        return waiters.size();
    }

    int pendingResponseCount() {
        synchronized (dispatchLock) {
            return pendingResponses.size();
        }
    }

    long pendingResponseBytes() {
        synchronized (dispatchLock) {
            return pendingResponses.totalBytes();
        }
    }

    static String requestId(String jsonBody) {
        try {
            JsonNode root = McpObjectMapper.INSTANCE.readTree(jsonBody);
            JsonNode idNode = root == null ? null : root.get("id");
            return idNode != null && (idNode.isNumber() || idNode.isTextual()) ? idNode.asText() : null;
        } catch (IOException e) {
            return null;
        }
    }

    private void buffer(String id, StreamedReply reply) {
        long budget = pendingResponseBudget.getAsLong();
        List<String> evicted = pendingResponses.put(id, reply, budget);
        if (!evicted.isEmpty()) {
            eventLog.warn("Unclaimed SSE response buffer exceeded " + budget + " bytes; discarded "
                    + evicted.size() + " oldest unmatched response(s). Raise the limit in Settings if "
                    + "scan requests time out.");
        }
    }

    private static String responseId(String data) {
        try {
            return Long.toString(McpResponses.parse(data, BoundedBodyReader.MAX_RESPONSE_BYTES).id());
        } catch (IllegalArgumentException unsupportedReply) {
            return requestId(data);
        }
    }
}
