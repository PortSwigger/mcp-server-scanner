package com.mcpscanner.client;

import com.mcpscanner.http.FlatHeaders;
import com.mcpscanner.http.evidence.BodyCapture;
import com.mcpscanner.mcp.BoundedBodyReader;
import com.mcpscanner.mcp.McpHeaders;
import com.mcpscanner.mcp.ServerPings;
import com.mcpscanner.core.protocol.McpFlow;
import com.mcpscanner.core.protocol.McpRequests;

import java.io.IOException;
import java.io.InputStream;
import java.net.URI;
import java.net.http.HttpTimeoutException;
import java.time.Duration;
import java.util.Map;

final class ProtocolHttpExchange {

    record Exchange(McpFlow.HttpResponse response, URI reachedUri) {}

    @FunctionalInterface
    private interface Send<T> {
        T run() throws IOException, InterruptedException;
    }

    private final ProtocolHttpTransport transport;
    private final Duration timeout;
    private final ProtocolBodyReader bodyReader;
    private final ServerPings serverPings;

    ProtocolHttpExchange(ProtocolHttpTransport transport, Duration timeout, ServerPings serverPings) {
        this.transport = transport;
        this.timeout = timeout;
        this.bodyReader = new ProtocolBodyReader(timeout);
        this.serverPings = serverPings;
    }

    SseReplyReader replyReader(InputStream sseStream) {
        return bodyReader.replyReader(sseStream);
    }

    Exchange exchange(URI target, McpRequests.Request request) {
        return unchecked(() -> read(target, request, send(target, request)));
    }

    SseMessagePost recordedPost(URI target, McpRequests.Request request) {
        return unchecked(() -> {
            ProtocolHttpResponse sent = send(target, request);
            BodyCapture body = new BodyCapture(sent.body(), BoundedBodyReader.MAX_RESPONSE_BYTES);
            Exchange exchange = read(target, request, sent.withBody(body));
            return new SseMessagePost(exchange.response(), sent.wire().map(body::completing));
        });
    }

    private Exchange read(URI target, McpRequests.Request request, ProtocolHttpResponse response)
            throws IOException, InterruptedException {
        String body = bodyReader.read(response, request.body(),
                serverPings.answerer(request.headers(), reply -> postDiscardingResponse(target, reply)));
        return new Exchange(new McpFlow.HttpResponse(response.status(), flowHeaders(response), body, true),
                response.uri());
    }

    private <T> T unchecked(Send<T> send) {
        try {
            return send.run();
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new IllegalStateException("MCP request interrupted", e);
        } catch (IOException e) {
            throw new IllegalStateException("MCP request failed: " + failureReason(e), e);
        }
    }

    void delete(URI target, Map<String, String> headers) throws IOException, InterruptedException {
        ProtocolHttpRequest delete = new ProtocolHttpRequest(target, "DELETE", headers, null);
        ProtocolBodyReader.closeQuietly(transport.send(delete, timeout).body());
    }

    private ProtocolHttpResponse send(URI target, McpRequests.Request request)
            throws IOException, InterruptedException {
        return transport.send(new ProtocolHttpRequest(target, "POST", request.headers(), request.body()), timeout);
    }

    private void postDiscardingResponse(URI target, McpRequests.Request request) {
        try {
            ProtocolBodyReader.closeQuietly(send(target, request).body());
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        } catch (IOException ignored) {
        }
    }

    private static Map<String, String> flowHeaders(ProtocolHttpResponse response) {
        Map<String, String> headers = FlatHeaders.of(response.headers());
        response.firstHeader(McpHeaders.SESSION_ID).ifPresent(value -> headers.put(McpHeaders.SESSION_ID, value));
        if (ProtocolBodyReader.isEventStream(response)) {
            headers.keySet().removeIf(name -> name.equalsIgnoreCase("Content-Type"));
            headers.put("Content-Type", "application/json");
        }
        return headers;
    }

    private String failureReason(IOException failure) {
        if (failure instanceof HttpTimeoutException) {
            return "no response within " + timeout.toSeconds() + " s";
        }
        return failure.getMessage() != null ? failure.getMessage() : failure.getClass().getSimpleName();
    }
}
