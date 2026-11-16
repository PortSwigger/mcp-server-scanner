package com.mcpscanner.checks.catalog.commandinjection;

import burp.api.montoya.http.Http;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.api.montoya.scanner.audit.insertionpoint.AuditInsertionPoint;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.mcpscanner.mcp.McpObjectMapper;
import com.mcpscanner.scan.McpInsertionPointProvider;

import java.util.ArrayList;
import java.util.List;
import java.util.function.Function;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

final class SimulatedToolServer {

    static final String ENDPOINT = "http://mcp.example/mcp";
    static final String BASE_VALUE = "example";

    record ToolReply(String text, boolean isError, boolean rpcError) {
        static ToolReply ok(String text) {
            return new ToolReply(text, false, false);
        }

        static ToolReply toolError(String text) {
            return new ToolReply(text, true, false);
        }

        static ToolReply rpcError(String text) {
            return new ToolReply(text, false, true);
        }
    }

    private final String tool;
    private final String argument;
    private final List<String> siblingArguments = new ArrayList<>();
    private final Function<String, ToolReply> behaviour;
    private final List<String> receivedValues = new ArrayList<>();
    private boolean sseReplies;
    private String endpoint = ENDPOINT;

    SimulatedToolServer(String tool, String argument, Function<String, ToolReply> behaviour) {
        this.tool = tool;
        this.argument = argument;
        this.behaviour = behaviour;
    }

    SimulatedToolServer alongside(String siblingArgument) {
        siblingArguments.add(siblingArgument);
        return this;
    }

    SimulatedToolServer atEndpoint(String url) {
        endpoint = url;
        return this;
    }

    HttpResponse replyTo(HttpRequest request) {
        return exchange(request).response();
    }

    SimulatedToolServer replyingWithSse() {
        sseReplies = true;
        return this;
    }

    Http http() {
        Http http = mock(Http.class);
        when(http.sendRequest(any(HttpRequest.class))).thenAnswer(invocation -> exchange(invocation.getArgument(0)));
        return http;
    }

    HttpRequestResponse baseline() {
        return exchange(request(toolCall(BASE_VALUE)));
    }

    HttpRequestResponse notificationBase() {
        return HttpRequestResponse.httpRequestResponse(request(
                "{\"jsonrpc\":\"2.0\",\"method\":\"notifications/progress\",\"params\":{\"progressToken\":\""
                        + BASE_VALUE + "\",\"progress\":1}}"), HttpResponse.httpResponse(raw(202, "")));
    }

    ProbeField probeField(HttpRequestResponse base) {
        AuditInsertionPoint field = argumentField(base);
        return new ProbeField(base, field, field.name(), http());
    }

    AuditInsertionPoint argumentField(HttpRequestResponse base) {
        return field(base, "params.arguments." + argument);
    }

    AuditInsertionPoint field(HttpRequestResponse base, String path) {
        return new McpInsertionPointProvider().provideInsertionPoints(base).stream()
                .filter(point -> point.name().endsWith(path))
                .findFirst()
                .orElseThrow();
    }

    List<String> receivedValues() {
        return List.copyOf(receivedValues);
    }

    int probeCount() {
        return receivedValues.size() - 1;
    }

    private HttpRequestResponse exchange(HttpRequest request) {
        JsonNode message = McpObjectMapper.INSTANCE.valueToTree(parse(request.bodyToString()));
        if (!message.has("id")) {
            receivedValues.add(message.path("params").path("progressToken").asText());
            return HttpRequestResponse.httpRequestResponse(request, HttpResponse.httpResponse(raw(202, "")));
        }
        String value = argumentNode(message.path("params").path("arguments"), argument).asText();
        receivedValues.add(value);
        String body = reply(message.get("id"), behaviour.apply(value));
        return HttpRequestResponse.httpRequestResponse(request,
                HttpResponse.httpResponse(raw(200, sseReplies ? "event: message\ndata: " + body + "\n\n" : body)));
    }

    private static String reply(JsonNode id, ToolReply reply) {
        ObjectNode envelope = McpObjectMapper.INSTANCE.createObjectNode().put("jsonrpc", "2.0");
        envelope.set("id", id);
        if (reply.rpcError()) {
            envelope.putObject("error").put("code", -32602).put("message", reply.text());
            return envelope.toString();
        }
        ObjectNode result = envelope.putObject("result");
        result.putArray("content").addObject().put("type", "text").put("text", reply.text());
        if (reply.isError()) {
            result.put("isError", true);
        }
        return envelope.toString();
    }

    private String toolCall(String value) {
        ObjectNode envelope = McpObjectMapper.INSTANCE.createObjectNode().put("jsonrpc", "2.0").put("id", 7)
                .put("method", "tools/call");
        ObjectNode params = envelope.putObject("params").put("name", tool);
        ObjectNode arguments = params.putObject("arguments");
        put(arguments, argument, value);
        siblingArguments.forEach(sibling -> put(arguments, sibling, BASE_VALUE));
        return envelope.toString();
    }

    private static void put(ObjectNode arguments, String dottedPath, String value) {
        String[] keys = dottedPath.split("\\.");
        ObjectNode parent = arguments;
        for (int index = 0; index < keys.length - 1; index++) {
            parent = parent.has(keys[index]) ? (ObjectNode) parent.get(keys[index]) : parent.putObject(keys[index]);
        }
        parent.put(keys[keys.length - 1], value);
    }

    private static JsonNode argumentNode(JsonNode arguments, String dottedPath) {
        JsonNode node = arguments;
        for (String key : dottedPath.split("\\.")) {
            node = node.path(key);
        }
        return node;
    }

    private HttpRequest request(String body) {
        return HttpRequest.httpRequestFromUrl(endpoint).withMethod("POST")
                .withAddedHeader("Content-Type", "application/json").withBody(body);
    }

    private static Object parse(String body) {
        try {
            return McpObjectMapper.INSTANCE.readValue(body, Object.class);
        } catch (Exception unparseable) {
            throw new IllegalStateException(unparseable);
        }
    }

    private static String raw(int status, String body) {
        return "HTTP/1.1 " + status + " X\r\nContent-Type: application/json\r\n\r\n" + body;
    }
}
