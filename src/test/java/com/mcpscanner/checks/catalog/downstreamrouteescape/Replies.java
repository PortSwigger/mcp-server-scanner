package com.mcpscanner.checks.catalog.downstreamrouteescape;

import com.mcpscanner.testutil.SpentRateLimitQuota;
import burp.api.montoya.http.message.HttpHeader;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.responses.HttpResponse;

import java.util.List;

import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.mock;

final class Replies {

    private Replies() {}

    static HttpRequestResponse toolText(String text) {
        return json(200, "{\"jsonrpc\":\"2.0\",\"id\":7,\"result\":{\"content\":[{\"type\":\"text\",\"text\":\""
                + text.replace("\"", "\\\"") + "\"}],\"isError\":false}}");
    }

    static HttpRequestResponse toolError(String text) {
        return json(200, "{\"jsonrpc\":\"2.0\",\"id\":7,\"result\":{\"content\":[{\"type\":\"text\",\"text\":\""
                + text + "\"}],\"isError\":true}}");
    }

    static HttpRequestResponse rpcError(String message) {
        return json(200, "{\"jsonrpc\":\"2.0\",\"id\":7,\"error\":{\"code\":-32602,\"message\":\"" + message + "\"}}");
    }

    static HttpRequestResponse json(int status, String body) {
        return exchange(status, "application/json", body);
    }

    static HttpRequestResponse exchange(int status, String contentType, String body) {
        HttpResponse response = mock(HttpResponse.class);
        lenient().when(response.statusCode()).thenReturn((short) status);
        lenient().when(response.bodyToString()).thenReturn(body);
        lenient().when(response.headerValue("Content-Type")).thenReturn(contentType);
        HttpRequestResponse exchange = mock(HttpRequestResponse.class);
        lenient().when(exchange.response()).thenReturn(response);
        return exchange;
    }

    static HttpRequestResponse spentQuota(HttpRequestResponse reply) {
        List<HttpHeader> spent = SpentRateLimitQuota.mockedHeaders();
        HttpResponse response = reply.response();
        lenient().when(response.headers()).thenReturn(spent);
        return reply;
    }

    static HttpRequestResponse noResponse() {
        return mock(HttpRequestResponse.class);
    }
}
