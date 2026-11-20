package com.mcpscanner.client;

import burp.api.montoya.http.Http;
import burp.api.montoya.http.RequestOptions;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import com.mcpscanner.core.protocol.McpRequests;
import com.mcpscanner.mcp.RawSseFrame;
import com.mcpscanner.mcp.ServerPings;
import com.mcpscanner.testutil.EvidenceTarget;

import java.io.InputStream;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Map;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

public final class EvidenceProducerFixtures {

    private EvidenceProducerFixtures() {
    }

    public static List<HttpRequestResponse> burpTransport(URI endpoint, Map<String, String> headers) throws Exception {
        HttpResponse reply = HttpResponse.httpResponse("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n"
                + EvidenceTarget.TOOLS_REPLY);
        Http burp = mock(Http.class);
        when(burp.sendRequest(any(HttpRequest.class), any(RequestOptions.class))).thenAnswer(invocation ->
                HttpRequestResponse.httpRequestResponse(invocation.getArgument(0), reply));
        try (BurpProtocolHttpTransport transport = new BurpProtocolHttpTransport(burp)) {
            ProtocolHttpResponse response = transport.send(post(endpoint, headers), EvidenceTarget.TIMEOUT);
            return List.of(response.wire().orElseThrow().evidence());
        }
    }

    public static List<HttpRequestResponse> toolsListRecorder(URI endpoint, Map<String, String> headers)
            throws Exception {
        ToolsListRecorder recorder = new ToolsListRecorder(new JdkProtocolHttpTransport(EvidenceTarget.jdkClient()));
        try (InputStream body = recorder.send(post(endpoint, headers), EvidenceTarget.TIMEOUT).body()) {
            body.readAllBytes();
        }
        return List.of(recorder.recorded().orElseThrow());
    }

    public static List<HttpRequestResponse> legacySse(URI endpoint, Map<String, String> headers) {
        ProtocolHttpExchange exchange = new ProtocolHttpExchange(
                new JdkProtocolHttpTransport(EvidenceTarget.jdkClient()), EvidenceTarget.TIMEOUT,
                new ServerPings(() -> false));
        McpRequests.Request request = new McpRequests.Request(EvidenceTarget.TOOLS_LIST, headers);
        SseStreamOpening opening = SseStreamOpenings.of(endpoint.toString(), headers,
                Map.of("Content-Type", List.of("text/event-stream")));
        SseToolsListRecorder recorder = new SseToolsListRecorder();
        recorder.messagePosted(opening, request, exchange.recordedPost(endpoint, request));
        recorder.eventReceived(opening, new RawSseFrame(EvidenceTarget.TOOLS_EVENT,
                EvidenceTarget.TOOLS_EVENT.getBytes(StandardCharsets.UTF_8)));
        return recorder.recorded();
    }

    private static ProtocolHttpRequest post(URI endpoint, Map<String, String> headers) {
        return new ProtocolHttpRequest(endpoint, "POST", headers, EvidenceTarget.TOOLS_LIST);
    }
}
