package com.mcpscanner.client;

import com.fasterxml.jackson.databind.JsonNode;
import com.mcpscanner.mcp.McpObjectMapper;
import dev.langchain4j.mcp.client.McpCallContext;
import dev.langchain4j.mcp.client.transport.McpTransport;
import dev.langchain4j.mcp.protocol.McpClientMessage;
import dev.langchain4j.mcp.protocol.McpClientMethod;
import dev.langchain4j.mcp.protocol.McpInitializeRequest;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.junit.jupiter.MockitoExtension;

import java.net.URI;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.CompletableFuture;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class CapturingMcpTransportTest {

    @Test
    void returnsNullInitializeResultBeforeAnyCall() {
        McpTransport delegate = mock(McpTransport.class);
        CapturingMcpTransport captor = new CapturingMcpTransport(delegate);

        assertThat(captor.initializeResult()).isNull();
    }

    @Test
    void capturesJsonNodeReturnedByDelegateInitialize() throws Exception {
        JsonNode envelope = McpObjectMapper.INSTANCE.readTree(
                "{\"jsonrpc\":\"2.0\",\"id\":42,\"result\":{"
                        + "\"serverInfo\":{\"name\":\"captured\",\"version\":\"1.0\"}}}");
        McpTransport delegate = mock(McpTransport.class);
        when(delegate.initialize(any(McpInitializeRequest.class)))
                .thenReturn(CompletableFuture.completedFuture(envelope));
        CapturingMcpTransport captor = new CapturingMcpTransport(delegate);

        captor.initialize(new McpInitializeRequest(42L)).get();

        assertThat(captor.initializeResult()).isEqualTo(envelope);
    }

    @Test
    void doesNotOverwriteCaptureWhenDelegateFutureFails() throws Exception {
        // If a follow-up initialize ever fails, prefer the previously captured envelope over null:
        // an earlier successful capture is more useful than discarding metadata on a transient error.
        JsonNode envelope = McpObjectMapper.INSTANCE.readTree(
                "{\"result\":{\"serverInfo\":{\"name\":\"sticky\"}}}");
        McpTransport delegate = mock(McpTransport.class);
        when(delegate.initialize(any(McpInitializeRequest.class)))
                .thenReturn(CompletableFuture.completedFuture(envelope));
        CapturingMcpTransport captor = new CapturingMcpTransport(delegate);
        captor.initialize(new McpInitializeRequest(1L)).get();

        CompletableFuture<JsonNode> failing = new CompletableFuture<>();
        failing.completeExceptionally(new RuntimeException("boom"));
        when(delegate.initialize(any(McpInitializeRequest.class))).thenReturn(failing);
        try {
            captor.initialize(new McpInitializeRequest(2L)).get();
        } catch (Exception ignored) {
            // expected
        }

        assertThat(captor.initializeResult()).isEqualTo(envelope);
    }

    @Test
    void delegatesCloseToUnderlyingTransport() throws Exception {
        McpTransport delegate = mock(McpTransport.class);
        CapturingMcpTransport captor = new CapturingMcpTransport(delegate);

        captor.close();

        verify(delegate).close();
    }

    @Test
    void capturesToolsListEnvelope() throws Exception {
        // langchain4j's DefaultMcpClient.obtainToolList drives the transport via the
        // McpCallContext overload of executeOperationWithResponse. The decorator must
        // stash the JSON-RPC envelope returned for that call so callers can extract
        // icons (which langchain4j-mcp 1.15.0-beta25 does not yet surface natively).
        JsonNode envelope = McpObjectMapper.INSTANCE.readTree(
                "{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{\"tools\":["
                        + "{\"name\":\"hello\",\"icons\":["
                        + "{\"src\":\"data:image/png;base64,iVBORw0K\",\"mimeType\":\"image/png\"}]}]}}");
        McpTransport delegate = mock(McpTransport.class);
        when(delegate.executeOperationWithResponse(any(McpCallContext.class)))
                .thenReturn(CompletableFuture.completedFuture(envelope));
        CapturingMcpTransport captor = new CapturingMcpTransport(delegate);

        McpCallContext context = new McpCallContext(null,
                new McpClientMessage(1L, McpClientMethod.TOOLS_LIST));
        captor.executeOperationWithResponse(context).get();

        assertThat(captor.toolsListResult()).isEqualTo(envelope);
    }

    @Test
    void capturesResourcesListEnvelope() throws Exception {
        JsonNode envelope = McpObjectMapper.INSTANCE.readTree(
                "{\"jsonrpc\":\"2.0\",\"id\":2,\"result\":{\"resources\":["
                        + "{\"name\":\"readme\",\"icons\":["
                        + "{\"src\":\"https://cdn.example/readme.png\"}]}]}}");
        McpTransport delegate = mock(McpTransport.class);
        when(delegate.executeOperationWithResponse(any(McpCallContext.class)))
                .thenReturn(CompletableFuture.completedFuture(envelope));
        CapturingMcpTransport captor = new CapturingMcpTransport(delegate);

        McpCallContext context = new McpCallContext(null,
                new McpClientMessage(2L, McpClientMethod.RESOURCES_LIST));
        captor.executeOperationWithResponse(context).get();

        assertThat(captor.resourcesListResult()).isEqualTo(envelope);
    }

    @Test
    void capturesPromptsListEnvelope() throws Exception {
        JsonNode envelope = McpObjectMapper.INSTANCE.readTree(
                "{\"jsonrpc\":\"2.0\",\"id\":3,\"result\":{\"prompts\":["
                        + "{\"name\":\"summarise\",\"icons\":["
                        + "{\"src\":\"https://cdn.example/p.svg\",\"mimeType\":\"image/svg+xml\"}]}]}}");
        McpTransport delegate = mock(McpTransport.class);
        when(delegate.executeOperationWithResponse(any(McpCallContext.class)))
                .thenReturn(CompletableFuture.completedFuture(envelope));
        CapturingMcpTransport captor = new CapturingMcpTransport(delegate);

        McpCallContext context = new McpCallContext(null,
                new McpClientMessage(3L, McpClientMethod.PROMPTS_LIST));
        captor.executeOperationWithResponse(context).get();

        assertThat(captor.promptsListResult()).isEqualTo(envelope);
    }

    @Test
    void doesNotOverwriteListCapturesForUnrelatedMethods() throws Exception {
        JsonNode toolsEnvelope = McpObjectMapper.INSTANCE.readTree(
                "{\"result\":{\"tools\":[{\"name\":\"hello\"}]}}");
        JsonNode otherEnvelope = McpObjectMapper.INSTANCE.readTree(
                "{\"result\":{\"content\":\"ignored\"}}");
        McpTransport delegate = mock(McpTransport.class);
        when(delegate.executeOperationWithResponse(any(McpCallContext.class)))
                .thenReturn(CompletableFuture.completedFuture(toolsEnvelope))
                .thenReturn(CompletableFuture.completedFuture(otherEnvelope));
        CapturingMcpTransport captor = new CapturingMcpTransport(delegate);

        captor.executeOperationWithResponse(new McpCallContext(null,
                new McpClientMessage(1L, McpClientMethod.TOOLS_LIST))).get();
        captor.executeOperationWithResponse(new McpCallContext(null,
                new McpClientMessage(2L, McpClientMethod.PING))).get();

        assertThat(captor.toolsListResult()).isEqualTo(toolsEnvelope);
        assertThat(captor.resourcesListResult()).isNull();
        assertThat(captor.promptsListResult()).isNull();
    }

    // ---------------------------------------------------------------------------------------
    // Exchange-publisher hook: feeds langchain4j discovery into the audit bridge so
    // Burp's passive-scan engine can re-emit the (request, response) pair through
    // JsonRpcDiscoveryResponseScanner. Each publish carries the wire-method name, the
    // endpoint URL, the synthesised JSON-RPC request body, and the JsonNode envelope —
    // enough to rebuild an HttpRequestResponse without round-tripping over the wire.
    // ---------------------------------------------------------------------------------------

    @Test
    void publishesCapturedExchangeForInitializeOnSuccessfulCompletion() throws Exception {
        JsonNode envelope = McpObjectMapper.INSTANCE.readTree(
                "{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{\"protocolVersion\":\"2024-11-05\"}}");
        McpTransport delegate = mock(McpTransport.class);
        when(delegate.initialize(any(McpInitializeRequest.class)))
                .thenReturn(CompletableFuture.completedFuture(envelope));
        List<CapturedExchange> captured = new ArrayList<>();
        CapturingMcpTransport captor = new CapturingMcpTransport(
                delegate, URI.create("http://localhost:8080/mcp"), captured::add);

        captor.initialize(new McpInitializeRequest(1L)).get();

        assertThat(captured).hasSize(1);
        CapturedExchange exchange = captured.get(0);
        assertThat(exchange.jsonRpcMethod()).isEqualTo("initialize");
        assertThat(exchange.url()).isEqualTo(URI.create("http://localhost:8080/mcp"));
        assertThat(exchange.responseEnvelope()).isEqualTo(envelope);
        assertThat(exchange.requestBody()).contains("\"method\":\"initialize\"");
        assertThat(exchange.requestBody()).contains("\"jsonrpc\":\"2.0\"");
    }

    @Test
    void publishesCapturedExchangeForToolsListOnSuccessfulCompletion() throws Exception {
        JsonNode envelope = McpObjectMapper.INSTANCE.readTree(
                "{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{\"tools\":[{\"name\":\"x\"}]}}");
        McpTransport delegate = mock(McpTransport.class);
        when(delegate.executeOperationWithResponse(any(McpCallContext.class)))
                .thenReturn(CompletableFuture.completedFuture(envelope));
        List<CapturedExchange> captured = new ArrayList<>();
        CapturingMcpTransport captor = new CapturingMcpTransport(
                delegate, URI.create("http://localhost:8080/mcp"), captured::add);

        captor.executeOperationWithResponse(new McpCallContext(null,
                new McpClientMessage(1L, McpClientMethod.TOOLS_LIST))).get();

        assertThat(captured).hasSize(1);
        assertThat(captured.get(0).jsonRpcMethod()).isEqualTo("tools/list");
        assertThat(captured.get(0).requestBody()).contains("\"method\":\"tools/list\"");
    }

    @Test
    void publishesCapturedExchangeForResourcesAndPromptsList() throws Exception {
        JsonNode resources = McpObjectMapper.INSTANCE.readTree(
                "{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{\"resources\":[]}}");
        JsonNode prompts = McpObjectMapper.INSTANCE.readTree(
                "{\"jsonrpc\":\"2.0\",\"id\":2,\"result\":{\"prompts\":[]}}");
        McpTransport delegate = mock(McpTransport.class);
        when(delegate.executeOperationWithResponse(any(McpCallContext.class)))
                .thenReturn(CompletableFuture.completedFuture(resources))
                .thenReturn(CompletableFuture.completedFuture(prompts));
        List<CapturedExchange> captured = new ArrayList<>();
        CapturingMcpTransport captor = new CapturingMcpTransport(
                delegate, URI.create("http://localhost:8080/mcp"), captured::add);

        captor.executeOperationWithResponse(new McpCallContext(null,
                new McpClientMessage(1L, McpClientMethod.RESOURCES_LIST))).get();
        captor.executeOperationWithResponse(new McpCallContext(null,
                new McpClientMessage(2L, McpClientMethod.PROMPTS_LIST))).get();

        assertThat(captured).hasSize(2);
        assertThat(captured.get(0).jsonRpcMethod()).isEqualTo("resources/list");
        assertThat(captured.get(1).jsonRpcMethod()).isEqualTo("prompts/list");
    }

    @Test
    void doesNotPublishForNonDiscoveryMethods() throws Exception {
        // PING / TOOLS_CALL / etc. must not enter the audit bridge — only the four
        // discovery methods that JsonRpcDiscoveryResponseScanner's classifier accepts.
        JsonNode envelope = McpObjectMapper.INSTANCE.readTree(
                "{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{\"content\":[]}}");
        McpTransport delegate = mock(McpTransport.class);
        when(delegate.executeOperationWithResponse(any(McpCallContext.class)))
                .thenReturn(CompletableFuture.completedFuture(envelope));
        List<CapturedExchange> captured = new ArrayList<>();
        CapturingMcpTransport captor = new CapturingMcpTransport(
                delegate, URI.create("http://localhost:8080/mcp"), captured::add);

        captor.executeOperationWithResponse(new McpCallContext(null,
                new McpClientMessage(1L, McpClientMethod.PING))).get();
        captor.executeOperationWithResponse(new McpCallContext(null,
                new McpClientMessage(2L, McpClientMethod.TOOLS_CALL))).get();
        captor.executeOperationWithResponse(new McpCallContext(null,
                new McpClientMessage(3L, McpClientMethod.RESOURCES_TEMPLATES_LIST))).get();

        assertThat(captured).isEmpty();
    }

    @Test
    void doesNotPublishWhenFutureFails() throws Exception {
        McpTransport delegate = mock(McpTransport.class);
        CompletableFuture<JsonNode> failing = new CompletableFuture<>();
        failing.completeExceptionally(new RuntimeException("transport boom"));
        when(delegate.executeOperationWithResponse(any(McpCallContext.class))).thenReturn(failing);
        List<CapturedExchange> captured = new ArrayList<>();
        CapturingMcpTransport captor = new CapturingMcpTransport(
                delegate, URI.create("http://localhost:8080/mcp"), captured::add);

        try {
            captor.executeOperationWithResponse(new McpCallContext(null,
                    new McpClientMessage(1L, McpClientMethod.TOOLS_LIST))).get();
        } catch (Exception ignored) {
            // expected
        }

        assertThat(captured).isEmpty();
    }

    @Test
    void publisherIsOptional_legacyConstructorStillWorks() throws Exception {
        // Existing callers that only need the capture slots (icons, server info) must
        // continue to work — the publisher is optional.
        JsonNode envelope = McpObjectMapper.INSTANCE.readTree(
                "{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{\"tools\":[]}}");
        McpTransport delegate = mock(McpTransport.class);
        when(delegate.executeOperationWithResponse(any(McpCallContext.class)))
                .thenReturn(CompletableFuture.completedFuture(envelope));
        CapturingMcpTransport captor = new CapturingMcpTransport(delegate);

        captor.executeOperationWithResponse(new McpCallContext(null,
                new McpClientMessage(1L, McpClientMethod.TOOLS_LIST))).get();

        assertThat(captor.toolsListResult()).isEqualTo(envelope);
    }

    @Test
    void publishesPostAndJsonContentTypeHeader() throws Exception {
        // T8's HTTP-layer filter requires POST + Content-Type: application/json.
        JsonNode envelope = McpObjectMapper.INSTANCE.readTree(
                "{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{\"tools\":[]}}");
        McpTransport delegate = mock(McpTransport.class);
        when(delegate.executeOperationWithResponse(any(McpCallContext.class)))
                .thenReturn(CompletableFuture.completedFuture(envelope));
        List<CapturedExchange> captured = new ArrayList<>();
        CapturingMcpTransport captor = new CapturingMcpTransport(
                delegate, URI.create("http://localhost:8080/mcp"), captured::add);

        captor.executeOperationWithResponse(new McpCallContext(null,
                new McpClientMessage(1L, McpClientMethod.TOOLS_LIST))).get();

        CapturedExchange exchange = captured.get(0);
        assertThat(exchange.requestHeaders().get("Content-Type")).isEqualTo("application/json");
    }

    @Test
    void doesNotOverwriteListCaptureWhenDelegateFails() throws Exception {
        JsonNode envelope = McpObjectMapper.INSTANCE.readTree(
                "{\"result\":{\"tools\":[{\"name\":\"hello\"}]}}");
        McpTransport delegate = mock(McpTransport.class);
        when(delegate.executeOperationWithResponse(any(McpCallContext.class)))
                .thenReturn(CompletableFuture.completedFuture(envelope));
        CapturingMcpTransport captor = new CapturingMcpTransport(delegate);
        captor.executeOperationWithResponse(new McpCallContext(null,
                new McpClientMessage(1L, McpClientMethod.TOOLS_LIST))).get();

        CompletableFuture<JsonNode> failing = new CompletableFuture<>();
        failing.completeExceptionally(new RuntimeException("boom"));
        when(delegate.executeOperationWithResponse(any(McpCallContext.class))).thenReturn(failing);
        try {
            captor.executeOperationWithResponse(new McpCallContext(null,
                    new McpClientMessage(2L, McpClientMethod.TOOLS_LIST))).get();
        } catch (Exception ignored) {
            // expected
        }

        assertThat(captor.toolsListResult()).isEqualTo(envelope);
    }
}
