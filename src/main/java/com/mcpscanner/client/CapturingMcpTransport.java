package com.mcpscanner.client;

import com.fasterxml.jackson.databind.JsonNode;
import dev.langchain4j.mcp.client.McpCallContext;
import dev.langchain4j.mcp.client.transport.McpOperationHandler;
import dev.langchain4j.mcp.client.transport.McpTransport;
import dev.langchain4j.mcp.protocol.McpClientMessage;
import dev.langchain4j.mcp.protocol.McpClientMethod;
import dev.langchain4j.mcp.protocol.McpInitializeRequest;

import java.io.IOException;
import java.net.URI;
import java.util.Map;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.Consumer;

/**
 * Transport decorator that captures the JSON-RPC envelopes returned by langchain4j's
 * MCP transport so callers can read fields langchain4j-mcp does not yet surface
 * natively (server-info from {@code initialize}, icons from {@code tools/list},
 * {@code resources/list}, and {@code prompts/list}).
 *
 * <p>Wrapping the transport is the smallest surface that lets us reuse langchain4j's
 * transport-correct dance on both SSE (event-stream delivery) and Streamable HTTP
 * (inline JSON body) without forking it. A direct HTTP POST against SSE servers gets
 * 202-empty and silently drops the response, so going through the transport is the
 * only way to receive these envelopes reliably on both protocols.
 *
 * <p>Optionally publishes each captured discovery exchange to a downstream
 * {@link Consumer Consumer&lt;CapturedExchange&gt;} (typically
 * {@link McpDiscoveryAuditBridge}). The publisher is invoked only for the four
 * discovery methods that {@code JsonRpcDiscoveryResponseScanner}
 * recognises ({@code initialize}, {@code tools/list}, {@code resources/list},
 * {@code prompts/list}). Other operations (notifications, ping, tools/call) are
 * deliberately skipped so the bridge cannot accidentally feed non-discovery traffic
 * into the audit pipeline.
 */
final class CapturingMcpTransport implements McpTransport {

    private static final Map<McpClientMethod, String> WIRE_METHOD_NAMES = Map.of(
            McpClientMethod.INITIALIZE, "initialize",
            McpClientMethod.TOOLS_LIST, "tools/list",
            McpClientMethod.RESOURCES_LIST, "resources/list",
            McpClientMethod.PROMPTS_LIST, "prompts/list");

    private static final String JSON_CONTENT_TYPE = "application/json";

    private final McpTransport delegate;
    private final URI endpointUrl;
    private final Consumer<CapturedExchange> publisher;
    private final AtomicReference<JsonNode> initializeResult = new AtomicReference<>();
    private final Map<McpClientMethod, AtomicReference<JsonNode>> capturedListResults = Map.of(
            McpClientMethod.TOOLS_LIST, new AtomicReference<>(),
            McpClientMethod.RESOURCES_LIST, new AtomicReference<>(),
            McpClientMethod.PROMPTS_LIST, new AtomicReference<>());

    CapturingMcpTransport(McpTransport delegate) {
        this(delegate, null, null);
    }

    CapturingMcpTransport(McpTransport delegate, URI endpointUrl, Consumer<CapturedExchange> publisher) {
        this.delegate = delegate;
        this.endpointUrl = endpointUrl;
        this.publisher = publisher;
    }

    JsonNode initializeResult() {
        return initializeResult.get();
    }

    JsonNode toolsListResult() {
        return capturedListResults.get(McpClientMethod.TOOLS_LIST).get();
    }

    JsonNode resourcesListResult() {
        return capturedListResults.get(McpClientMethod.RESOURCES_LIST).get();
    }

    JsonNode promptsListResult() {
        return capturedListResults.get(McpClientMethod.PROMPTS_LIST).get();
    }

    @Override
    public void start(McpOperationHandler handler) {
        delegate.start(handler);
    }

    @Override
    public CompletableFuture<JsonNode> initialize(McpInitializeRequest request) {
        long id = request.getId() == null ? 0L : request.getId();
        return delegate.initialize(request).whenComplete((result, error) -> {
            if (error == null && result != null) {
                initializeResult.set(result);
                publishIfDiscovery(McpClientMethod.INITIALIZE, id, result);
            }
        });
    }

    @Override
    public CompletableFuture<JsonNode> executeOperationWithResponse(McpClientMessage message) {
        long id = idOrZero(message);
        return delegate.executeOperationWithResponse(message).whenComplete((result, error) -> {
            if (error == null && result != null && message != null) {
                publishIfDiscovery(message.method, id, result);
            }
        });
    }

    @Override
    public CompletableFuture<JsonNode> executeOperationWithResponse(McpCallContext context) {
        CompletableFuture<JsonNode> future = delegate.executeOperationWithResponse(context);
        McpClientMessage message = context == null ? null : context.message();
        if (message == null) {
            return future;
        }
        AtomicReference<JsonNode> slot = capturedListResults.get(message.method);
        long id = idOrZero(message);
        return future.whenComplete((result, error) -> {
            if (error == null && result != null) {
                if (slot != null) {
                    slot.set(result);
                }
                publishIfDiscovery(message.method, id, result);
            }
        });
    }

    private static long idOrZero(McpClientMessage message) {
        return message == null || message.getId() == null ? 0L : message.getId();
    }

    private void publishIfDiscovery(McpClientMethod method, long id, JsonNode responseEnvelope) {
        if (publisher == null || endpointUrl == null) {
            return;
        }
        String wireMethod = WIRE_METHOD_NAMES.get(method);
        if (wireMethod == null) {
            return;
        }
        String requestBody = "{\"jsonrpc\":\"2.0\",\"id\":" + id + ",\"method\":\"" + wireMethod + "\"}";
        try {
            publisher.accept(new CapturedExchange(
                    wireMethod,
                    endpointUrl,
                    Map.of("Content-Type", JSON_CONTENT_TYPE),
                    requestBody,
                    responseEnvelope));
        } catch (RuntimeException ignored) {
            // Never let a downstream sink failure poison the langchain4j transport future.
        }
    }

    @Override
    public void executeOperationWithoutResponse(McpClientMessage message) {
        delegate.executeOperationWithoutResponse(message);
    }

    @Override
    public void executeOperationWithoutResponse(McpCallContext context) {
        delegate.executeOperationWithoutResponse(context);
    }

    @Override
    public void checkHealth() {
        delegate.checkHealth();
    }

    @Override
    public void onFailure(Runnable handler) {
        delegate.onFailure(handler);
    }

    @Override
    public void close() throws IOException {
        delegate.close();
    }
}
