package com.mcpscanner.client;

import burp.api.montoya.http.message.HttpRequestResponse;
import com.fasterxml.jackson.core.JacksonException;
import com.mcpscanner.http.evidence.BodyCapture;
import com.mcpscanner.http.evidence.WireRecord;
import com.mcpscanner.mcp.BoundedBodyReader;
import com.mcpscanner.mcp.McpMethods;
import com.mcpscanner.mcp.McpObjectMapper;

import java.io.IOException;
import java.time.Duration;
import java.util.Optional;
import java.util.concurrent.atomic.AtomicReference;

final class ToolsListRecorder implements ProtocolHttpTransport {

    private final ProtocolHttpTransport delegate;
    private final AtomicReference<HttpRequestResponse> recorded = new AtomicReference<>();

    ToolsListRecorder(ProtocolHttpTransport delegate) {
        this.delegate = delegate;
    }

    @Override
    public ProtocolHttpResponse send(ProtocolHttpRequest request, Duration timeout)
            throws IOException, InterruptedException {
        ProtocolHttpResponse response = delegate.send(request, timeout);
        return recorded.get() == null && listsTools(request) ? recordOnClose(response) : response;
    }

    Optional<HttpRequestResponse> recorded() {
        return Optional.ofNullable(recorded.get());
    }

    private ProtocolHttpResponse recordOnClose(ProtocolHttpResponse response) {
        return response.wire()
                .map(wire -> response.withBody(new BodyCapture(response.body(), BoundedBodyReader.MAX_RESPONSE_BYTES,
                        body -> record(wire, body))))
                .orElse(response);
    }

    private void record(WireRecord wire, BodyCapture body) {
        if (body.captured().length > 0) {
            recorded.compareAndSet(null, body.completing(wire).evidence());
        }
    }

    private static boolean listsTools(ProtocolHttpRequest request) {
        if (!request.hasBody()) {
            return false;
        }
        try {
            return McpMethods.TOOLS_LIST.equals(McpObjectMapper.INSTANCE.readTree(request.body()).path("method").asText());
        } catch (JacksonException notJson) {
            return false;
        }
    }
}
