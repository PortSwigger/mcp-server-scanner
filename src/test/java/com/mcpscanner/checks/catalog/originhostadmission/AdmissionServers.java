package com.mcpscanner.checks.catalog.originhostadmission;

import burp.api.montoya.http.Http;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import com.mcpscanner.testutil.ImmutableHttpRequest;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.function.Function;
import java.util.function.Predicate;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

final class AdmissionServers {

    static final String LOOPBACK_URL = "http://127.0.0.1:8765/mcp";
    static final String PUBLIC_URL = "https://mcp.example.com/mcp";
    static final String TOOLS_LIST = "{\"jsonrpc\":\"2.0\",\"id\":3,\"method\":\"tools/list\",\"params\":{}}";
    static final String TOOLS_RESULT = "{\"jsonrpc\":\"2.0\",\"id\":3,\"result\":{\"tools\":[{\"name\":\"read_note\"}]}}";
    static final String OTHER_TOOLS_RESULT = "{\"jsonrpc\":\"2.0\",\"id\":3,\"result\":{\"tools\":[]}}";
    static final String FORBIDDEN = "{\"error\":\"origin not allowed\"}";

    private AdmissionServers() {}

    static HttpRequest seed(String url, String body) {
        Map<String, String> headers = new LinkedHashMap<>();
        headers.put("Content-Type", "application/json");
        headers.put("Accept", "application/json, text/event-stream");
        return ImmutableHttpRequest.post(url, headers, body);
    }

    static HttpRequest toolsList(String url) {
        return seed(url, TOOLS_LIST);
    }

    static HttpRequestResponse captured(HttpRequest request) {
        return HttpRequestResponse.httpRequestResponse(request, ok(TOOLS_RESULT));
    }

    static Function<HttpRequest, HttpResponse> admitting(Predicate<HttpRequest> admits) {
        return request -> admits.test(request) ? ok(TOOLS_RESULT) : status(403, FORBIDDEN);
    }

    static Predicate<HttpRequest> hostIsCaptured() {
        return request -> hostOf(request.url()).equals(request.headerValue("Host"));
    }

    static Predicate<HttpRequest> noForeignOrigin() {
        return request -> request.headerValue("Origin") == null;
    }

    static Predicate<HttpRequest> originMatchesHost() {
        return request -> Optional.ofNullable(request.headerValue("Origin"))
                .map(origin -> origin.equals("http://" + request.headerValue("Host")))
                .orElse(true);
    }

    static HttpResponse ok(String body) {
        return HttpResponse.httpResponse("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n" + body);
    }

    static HttpResponse sse(String body) {
        return HttpResponse.httpResponse("HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\n\r\n" + body);
    }

    static HttpResponse status(int status, String body) {
        return HttpResponse.httpResponse("HTTP/1.1 " + status + " X\r\nContent-Type: application/json\r\n\r\n" + body);
    }

    static String hostOf(String url) {
        java.net.URI uri = java.net.URI.create(url);
        return uri.getPort() == -1 ? uri.getHost() : uri.getHost() + ":" + uri.getPort();
    }

    static final class Server {

        final List<HttpRequest> received = new ArrayList<>();
        final Http http = mock(Http.class);

        Server(Function<HttpRequest, HttpResponse> behaviour) {
            when(http.sendRequest(any(HttpRequest.class))).thenAnswer(invocation -> {
                HttpRequest request = invocation.getArgument(0);
                received.add(request);
                return HttpRequestResponse.httpRequestResponse(request, behaviour.apply(request));
            });
        }

        List<HttpRequest> replays() {
            return received.stream().filter(request -> !request.method().equals("OPTIONS")).toList();
        }

        static Server sequenced(List<HttpResponse> responses) {
            List<HttpResponse> queue = new ArrayList<>(responses);
            return new Server(request -> queue.size() > 1 ? queue.remove(0) : queue.get(0));
        }
    }
}
