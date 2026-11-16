package com.mcpscanner.checks.catalog.sqlinjection;

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

final class SimulatedDatabaseServer {

    static final String ENDPOINT = "http://mcp.example/mcp";
    static final String RESOURCE_PREFIX = "sqlite://";
    static final String RESOURCE_SUFFIX = "/data";

    private final String method;
    private final String operation;
    private final String argument;
    private final String baseValue;
    private final Function<String, ToolReply> behaviour;
    private final List<String> receivedValues = new ArrayList<>();

    private SimulatedDatabaseServer(String method, String operation, String argument, String baseValue,
                                    Function<String, ToolReply> behaviour) {
        this.method = method;
        this.operation = operation;
        this.argument = argument;
        this.baseValue = baseValue;
        this.behaviour = behaviour;
    }

    static SimulatedDatabaseServer tool(String tool, String argument, String baseValue,
                                        Function<String, ToolReply> behaviour) {
        return new SimulatedDatabaseServer("tools/call", tool, argument, baseValue, behaviour);
    }

    static SimulatedDatabaseServer tableResource(String table, Function<String, ToolReply> behaviour) {
        return new SimulatedDatabaseServer("resources/read", "", "uri", RESOURCE_PREFIX + table + RESOURCE_SUFFIX,
                uri -> behaviour.apply(hostOf(uri)));
    }

    Http http() {
        Http http = mock(Http.class);
        when(http.sendRequest(any(HttpRequest.class))).thenAnswer(invocation -> exchange(invocation.getArgument(0)));
        return http;
    }

    HttpRequestResponse baseline() {
        HttpRequestResponse base = exchange(request(baseValue));
        receivedValues.clear();
        return base;
    }

    AuditInsertionPoint field(HttpRequestResponse base) {
        String path = "tools/call".equals(method) ? "params.arguments." + argument : "params.uri";
        return new McpInsertionPointProvider().provideInsertionPoints(base).stream()
                .filter(point -> point.name().endsWith(path))
                .findFirst()
                .orElseThrow();
    }

    List<String> receivedValues() {
        return List.copyOf(receivedValues);
    }

    private HttpRequestResponse exchange(HttpRequest request) {
        JsonNode message = parse(request.bodyToString());
        JsonNode params = message.path("params");
        String value = "tools/call".equals(method) ? params.path("arguments").path(argument).asText()
                : params.path("uri").asText();
        receivedValues.add(value);
        return HttpRequestResponse.httpRequestResponse(request,
                HttpResponse.httpResponse(raw(reply(message.get("id"), behaviour.apply(value)))));
    }

    private String reply(JsonNode id, ToolReply reply) {
        ObjectNode envelope = McpObjectMapper.INSTANCE.createObjectNode().put("jsonrpc", "2.0");
        envelope.set("id", id);
        ObjectNode result = envelope.putObject("result");
        result.putArray("content").addObject().put("type", "text").put("text", reply.text());
        if (reply.isError()) {
            result.put("isError", true);
        }
        return envelope.toString();
    }

    private HttpRequest request(String value) {
        ObjectNode envelope = McpObjectMapper.INSTANCE.createObjectNode().put("jsonrpc", "2.0").put("id", 7)
                .put("method", method);
        ObjectNode params = envelope.putObject("params");
        if ("tools/call".equals(method)) {
            params.put("name", operation).putObject("arguments").put(argument, value);
        } else {
            params.put("uri", value);
        }
        return HttpRequest.httpRequestFromUrl(ENDPOINT).withMethod("POST")
                .withAddedHeader("Content-Type", "application/json").withBody(envelope.toString());
    }

    private static String hostOf(String uri) {
        String rest = uri.startsWith(RESOURCE_PREFIX) ? uri.substring(RESOURCE_PREFIX.length()) : uri;
        int slash = rest.indexOf('/');
        return slash < 0 ? rest : rest.substring(0, slash);
    }

    private static JsonNode parse(String body) {
        try {
            return McpObjectMapper.INSTANCE.readTree(body);
        } catch (Exception unparseable) {
            throw new IllegalStateException(unparseable);
        }
    }

    private static String raw(String body) {
        return "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n" + body;
    }
}
