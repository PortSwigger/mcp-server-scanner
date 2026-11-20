package com.mcpscanner.proxy;

import com.mcpscanner.mcp.BoundedBodyReader;
import com.mcpscanner.mcp.McpHeaders;
import com.mcpscanner.mcp.McpMethods;
import com.mcpscanner.core.protocol.ClientProfile;
import com.mcpscanner.core.protocol.McpRequests;
import com.mcpscanner.core.protocol.McpResponses;

import java.io.IOException;
import java.time.Duration;
import java.util.Map;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.TimeoutException;
import java.util.function.LongSupplier;
import java.util.function.Supplier;

final class SseSessionHandshake {

    @FunctionalInterface
    interface MessagePoster {
        MessagePostResult post(String body, Map<String, String> headers) throws IOException, InterruptedException;
    }

    private final SseReplyDispatcher replies;
    private final LongSupplier requestIds;
    private final Supplier<ClientProfile> clientProfile;
    private final Duration timeout;

    SseSessionHandshake(SseReplyDispatcher replies, LongSupplier requestIds,
                        Supplier<ClientProfile> clientProfile, Duration timeout) {
        this.replies = replies;
        this.requestIds = requestIds;
        this.clientProfile = clientProfile;
        this.timeout = timeout;
    }

    ProxyResponse perform(MessagePoster poster, Map<String, String> headers) throws IOException, InterruptedException {
        String protocolVersion = negotiatedProtocolVersion(headers);
        ProxyResponse rejection = initialize(poster, headers, protocolVersion);
        if (rejection != null) {
            return rejection;
        }
        MessagePostResult notification = poster.post(McpRequests.initialized(protocolVersion, null).body(), headers);
        return checked(notification, "notifications/initialized");
    }

    private ProxyResponse initialize(MessagePoster poster, Map<String, String> headers, String protocolVersion)
            throws IOException, InterruptedException {
        long id = requestIds.getAsLong();
        String replyId = String.valueOf(id);
        CompletableFuture<StreamedReply> reply = replies.expect(replyId);
        try {
            ProxyResponse rejection = checked(poster.post(initializeBody(id, protocolVersion), headers), "initialize");
            if (rejection == null) {
                requireMatchingReply(replies.await(reply, timeout).json(), id);
            }
            return rejection;
        } catch (TimeoutException te) {
            throw new IOException("Timed out waiting for initialize response", te);
        } catch (ExecutionException ee) {
            throw handshakeFailure(ee);
        } finally {
            replies.release(replyId, reply);
        }
    }

    private String initializeBody(long id, String protocolVersion) {
        return McpRequests.envelope(McpMethods.INITIALIZE,
                McpRequests.initializeParams(protocolVersion, clientProfile.get()), id);
    }

    private static String negotiatedProtocolVersion(Map<String, String> headers) {
        return headers.entrySet().stream()
                .filter(header -> header.getKey().equalsIgnoreCase(McpHeaders.PROTOCOL_VERSION))
                .map(Map.Entry::getValue)
                .findFirst()
                .orElse(McpRequests.SSE_VERSION);
    }

    private static ProxyResponse checked(MessagePostResult result, String stage) throws IOException {
        if (result.isRefusal()) {
            return result.toProxyResponse();
        }
        if (!result.isSuccess()) {
            throw new IOException("Handshake " + stage + " POST returned status " + result.statusCode());
        }
        return null;
    }

    private static void requireMatchingReply(String reply, long id) throws IOException {
        if (McpResponses.parse(reply, BoundedBodyReader.MAX_RESPONSE_BYTES).id() != id) {
            throw new IOException("Initialize response ID did not match request");
        }
    }

    private static IOException handshakeFailure(ExecutionException failure) {
        Throwable cause = failure.getCause() != null ? failure.getCause() : failure;
        if (cause instanceof IOException io) {
            return io;
        }
        return new IOException("Initialize handshake failed: " + cause.getMessage(), cause);
    }
}
