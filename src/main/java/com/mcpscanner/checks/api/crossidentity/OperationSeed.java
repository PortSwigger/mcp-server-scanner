package com.mcpscanner.checks.api.crossidentity;

import com.mcpscanner.mcp.JsonLeaves;
import com.mcpscanner.mcp.Leaf;
import com.mcpscanner.checks.shared.session.SessionHeaders;
import burp.api.montoya.http.message.requests.HttpRequest;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.fasterxml.jackson.databind.node.TextNode;
import com.mcpscanner.checks.api.AccessItemKey;
import com.mcpscanner.checks.shared.jsonrpc.JsonRpcEnvelope;
import com.mcpscanner.mcp.McpHeaders;
import com.mcpscanner.mcp.McpObjectMapper;

import java.io.UncheckedIOException;
import java.util.List;
import java.util.Map;
import java.util.Optional;

public final class OperationSeed {

    private final HttpRequest request;
    private final AccessItemKey item;
    private final ObjectNode envelope;

    private OperationSeed(HttpRequest request, AccessItemKey item, ObjectNode envelope) {
        this.request = request;
        this.item = item;
        this.envelope = envelope;
    }

    public static Optional<OperationSeed> of(HttpRequest request) {
        if (request == null || !"POST".equals(request.method())) {
            return Optional.empty();
        }
        JsonRpcEnvelope parsed = JsonRpcEnvelope.of(request);
        if (!parsed.hasScalarId()) {
            return Optional.empty();
        }
        Optional<ObjectNode> root = parsed.root().filter(ObjectNode.class::isInstance).map(ObjectNode.class::cast);
        return AccessItemKey.fromEnvelope(parsed)
                .flatMap(item -> root.map(envelope -> new OperationSeed(request, item, envelope)));
    }

    public OperationSeed inSession(String sessionId) {
        return new OperationSeed(SessionHeaders.inSession(request, sessionId), item, envelope);
    }

    public HttpRequest request() {
        return request;
    }

    public AccessItemKey item() {
        return item;
    }

    public boolean toolCall() {
        return item.kind() == AccessItemKey.Kind.TOOL;
    }

    public String label() {
        return (toolCall() ? "tools/call " : "resources/read ") + item.name();
    }

    public Optional<String> sessionId() {
        return SessionHeaders.carriedBy(request);
    }

    public boolean stateful() {
        return sessionId().isPresent();
    }

    public Optional<String> protocolVersion() {
        return Optional.ofNullable(request.headerValue(McpHeaders.PROTOCOL_VERSION)).filter(value -> !value.isBlank());
    }

    public List<Leaf> selectorCandidates() {
        return toolCall() ? JsonLeaves.under(params().path(Leaf.ARGUMENTS), List.of(Leaf.ARGUMENTS))
                : List.of(new Leaf(List.of(Leaf.URI), TextNode.valueOf(item.name())));
    }

    public List<Leaf> referenceLeaves(String reference) {
        return selectorCandidates().stream().filter(leaf -> leaf.named(reference)).toList();
    }

    public HttpRequest withLeaves(HttpRequest target, Map<Leaf, JsonNode> values) {
        ObjectNode copy = envelope.deepCopy();
        ObjectNode params = (ObjectNode) copy.path("params");
        values.forEach((leaf, value) -> JsonLeaves.replace(params, leaf, value));
        return withEnvelope(target, copy);
    }

    public HttpRequest withAbsentTarget(HttpRequest target, AbsentValues absent) {
        ObjectNode copy = envelope.deepCopy();
        ObjectNode params = (ObjectNode) copy.path("params");
        if (toolCall()) {
            params.put("name", absent.name());
        } else {
            params.put(Leaf.URI, absent.uri(item.name()));
        }
        return withEnvelope(target, copy);
    }

    private ObjectNode params() {
        return (ObjectNode) envelope.path("params");
    }

    private static HttpRequest withEnvelope(HttpRequest target, JsonNode body) {
        try {
            return target.withBody(McpObjectMapper.INSTANCE.writeValueAsString(body));
        } catch (JsonProcessingException failure) {
            throw new UncheckedIOException(failure);
        }
    }
}
