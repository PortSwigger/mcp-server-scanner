package com.mcpscanner.client;

import com.fasterxml.jackson.databind.JsonNode;
import com.mcpscanner.mcp.McpHeaders;
import com.mcpscanner.mcp.McpMethods;
import com.mcpscanner.mcp.McpObjectMapper;
import com.mcpscanner.core.connection.HttpSession;
import com.mcpscanner.core.connection.McpConnection;
import com.mcpscanner.core.protocol.ClientProfile;
import com.mcpscanner.core.protocol.McpFlow;
import com.mcpscanner.core.protocol.McpRequests;

import java.io.IOException;
import java.net.URI;
import java.util.Map;
import java.util.Optional;

final class HttpBringUp {

    private final McpFlow flow;
    private final ProtocolHttpExchange exchange;
    private final ProtocolHttpExchange admissionExchange;
    private final ConnectionAttemptSink sink;

    HttpBringUp(McpFlow flow, ProtocolHttpExchange exchange, ProtocolHttpExchange admissionExchange,
                ConnectionAttemptSink sink) {
        this.flow = flow;
        this.exchange = exchange;
        this.admissionExchange = admissionExchange;
        this.sink = sink;
    }

    HttpSession open(ConnectionAttempt attempt, TransportType requestedTransport, ClientProfile profile) {
        McpFlow.HttpPort port = request -> send(requestedTransport, attempt, request);
        HttpSession selected = new McpConnection(flow, attempt.credentials()).openHttpSession(port, profile);
        if (requestedTransport == TransportType.MODERN_HTTP
                && !McpRequests.MODERN_VERSION.equals(selected.session().version())) {
            throw new IllegalStateException("Server did not accept modern HTTP");
        }
        return selected;
    }

    private McpFlow.HttpResponse send(TransportType requestedTransport, ConnectionAttempt attempt,
                                      McpRequests.Request request) {
        URI target = sink.endpointFor(attempt);
        Optional<McpFlow.HttpResponse> refused = wrongFramingReply(requestedTransport, request);
        if (refused.isPresent()) {
            return refused.get();
        }
        sink.rememberCredentials(attempt, request.headers());
        boolean admission = isAdmissionRequest(request);
        ProtocolHttpExchange.Exchange result = (admission ? admissionExchange : exchange).exchange(target, request);
        McpFlow.HttpResponse response = result.response();
        if (response.successful() && admission) {
            sink.recordAdmission(attempt, response.body(), result.reachedUri());
        }
        return response;
    }

    private static Optional<McpFlow.HttpResponse> wrongFramingReply(TransportType requestedTransport,
                                                                    McpRequests.Request request) {
        Optional<String> framedMethod = framedMethod(request);
        if (requestedTransport == TransportType.STREAMABLE_HTTP
                && framedMethod.filter(McpMethods.SERVER_DISCOVER::equals).isPresent()) {
            return Optional.of(emptyReply(404));
        }
        if (requestedTransport == TransportType.MODERN_HTTP && framedMethod.isEmpty()) {
            return Optional.of(emptyReply(400));
        }
        return Optional.empty();
    }

    private static McpFlow.HttpResponse emptyReply(int status) {
        return new McpFlow.HttpResponse(status, Map.of(), "", true);
    }

    private static boolean isAdmissionRequest(McpRequests.Request request) {
        Optional<String> method = framedMethod(request);
        if (method.isPresent()) return method.get().equals(McpMethods.SERVER_DISCOVER);
        try {
            JsonNode envelope = McpObjectMapper.INSTANCE.readTree(request.body());
            return envelope != null && McpMethods.INITIALIZE.equals(envelope.path("method").asText());
        } catch (IOException invalidBody) {
            return false;
        }
    }

    private static Optional<String> framedMethod(McpRequests.Request request) {
        return request.headers().entrySet().stream()
                .filter(header -> header.getKey().equalsIgnoreCase(McpHeaders.METHOD))
                .map(Map.Entry::getValue)
                .findFirst();
    }
}
