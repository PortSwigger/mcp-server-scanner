package com.mcpscanner.checks.catalog.outboundrequest;

import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.api.montoya.scanner.audit.insertionpoint.AuditInsertionPoint;
import com.mcpscanner.testutil.SpentRateLimitQuota;
import com.mcpscanner.scan.field.McpFieldGenerator;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

final class OutboundFixtures {

    static final String URL = "http://mcp.example.test/mcp";
    static final String TOOL_CALL = "{\"jsonrpc\":\"2.0\",\"id\":3,\"method\":\"tools/call\",\"params\":{"
            + "\"name\":\"render_report\",\"arguments\":{\"url\":\"https://docs.example.test/a\",\"limit\":5},"
            + "\"_meta\":{\"progressToken\":\"t1\"}}}";
    static final String FETCH_TOOL_CALL = "{\"jsonrpc\":\"2.0\",\"id\":6,\"method\":\"tools/call\",\"params\":{"
            + "\"name\":\"fetch\",\"arguments\":{\"url\":\"https://docs.example.test/a\",\"max_length\":5000}}}";
    static final String FETCH_PROMPT_GET = "{\"jsonrpc\":\"2.0\",\"id\":7,\"method\":\"prompts/get\",\"params\":{"
            + "\"name\":\"fetch\",\"arguments\":{\"url\":\"https://docs.example.test/a\"}}}";
    static final String SCRAPE_TOOL_CALL = "{\"jsonrpc\":\"2.0\",\"id\":8,\"method\":\"tools/call\",\"params\":{"
            + "\"name\":\"scrapePage\",\"arguments\":{\"pageUrl\":\"https://docs.example.test/a\"}}}";
    static final String VENDOR_FETCH_TOOL_CALL = "{\"jsonrpc\":\"2.0\",\"id\":9,\"method\":\"tools/call\",\"params\":{"
            + "\"name\":\"fetch_pagination_url\",\"arguments\":{\"url\":\"https://graph.example.test/next\","
            + "\"callback\":\"https://hooks.example.test/a\"}}}";
    static final String INITIALIZE = "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"initialize\",\"params\":{"
            + "\"protocolVersion\":\"2025-06-18\",\"capabilities\":{},"
            + "\"clientInfo\":{\"name\":\"scanner\",\"version\":\"1\",\"websiteUrl\":\"https://client.example.test\"}}}";
    static final String META_CLIENT_INFO = "{\"jsonrpc\":\"2.0\",\"id\":4,\"method\":\"tools/list\",\"params\":{"
            + "\"_meta\":{\"io.modelcontextprotocol/clientInfo\":{\"websiteUrl\":\"https://client.example.test\"}}}}";
    static final String RESOURCE_READ = "{\"jsonrpc\":\"2.0\",\"id\":5,\"method\":\"resources/read\","
            + "\"params\":{\"uri\":\"file:///notes/a.md\"}}";
    static final String NOTIFICATION = "{\"jsonrpc\":\"2.0\",\"method\":\"notifications/progress\","
            + "\"params\":{\"progressToken\":\"t1\",\"progress\":1}}";
    static final String REGISTRATION = "{\"redirect_uris\":[\"http://127.0.0.1:5000/cb\"],\"client_name\":\"c\","
            + "\"client_uri\":\"https://client.example.test\",\"logo_uri\":\"https://client.example.test/l.png\"}";
    static final String PLAIN_JSON = "{\"query\":\"https://example.test\"}";

    static final List<String> METHODS_WITH_PROGRESS_TOKEN = List.of(
            "{\"jsonrpc\":\"2.0\",\"id\":11,\"method\":\"tools/list\",\"params\":{\"_meta\":{\"progressToken\":\"t\"}}}",
            "{\"jsonrpc\":\"2.0\",\"id\":12,\"method\":\"resources/list\",\"params\":{\"_meta\":{\"progressToken\":\"t\"}}}",
            "{\"jsonrpc\":\"2.0\",\"id\":13,\"method\":\"prompts/list\",\"params\":{\"_meta\":{\"progressToken\":\"t\"}}}",
            TOOL_CALL,
            "{\"jsonrpc\":\"2.0\",\"id\":14,\"method\":\"resources/read\",\"params\":{\"uri\":\"file:///a\","
                    + "\"_meta\":{\"progressToken\":\"t\"}}}");
    static final String OTHER_TOOL_CALL = "{\"jsonrpc\":\"2.0\",\"id\":15,\"method\":\"tools/call\",\"params\":{"
            + "\"name\":\"archive_page\",\"arguments\":{\"url\":\"https://docs.example.test/b\"}}}";

    private OutboundFixtures() {}

    static HttpRequest mcpRequest(String body) {
        return post(URL, mcpHeaders(), body);
    }

    static HttpRequest mcpRequestWithHeader(String body, String name, String value) {
        Map<String, String> headers = mcpHeaders();
        headers.put(name, value);
        return post(URL, headers, body);
    }

    static HttpRequest jsonRequest(String url, String body) {
        return post(url, Map.of("Content-Type", "application/json"), body);
    }

    static HttpRequest post(String url, Map<String, String> headers, String body) {
        HttpRequest request = HttpRequest.httpRequestFromUrl(url).withMethod("POST");
        for (Map.Entry<String, String> header : headers.entrySet()) {
            request = request.withHeader(header.getKey(), header.getValue());
        }
        return request.withBody(body);
    }

    static HttpRequestResponse exchange(HttpRequest request) {
        return HttpRequestResponse.httpRequestResponse(request, okResponse());
    }

    static HttpResponse okResponse() {
        return HttpResponse.httpResponse("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n"
                + "{\"jsonrpc\":\"2.0\",\"id\":3,\"result\":{}}");
    }

    static HttpResponse quotaSpent() {
        return HttpResponse.httpResponse("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n"
                + SpentRateLimitQuota.HEADER_LINES + "\r\n{\"jsonrpc\":\"2.0\",\"id\":3,\"result\":{}}");
    }

    static HttpResponse tooManyRequests() {
        return HttpResponse.httpResponse("HTTP/1.1 429 Too Many Requests\r\nContent-Type: text/plain\r\n\r\nslow down");
    }

    static List<AuditInsertionPoint> fieldsOf(HttpRequest request) {
        return new McpFieldGenerator(() -> true).fieldsOf(request);
    }

    static AuditInsertionPoint field(HttpRequest request, String name) {
        return fieldsOf(request).stream().filter(point -> point.name().equals(name)).findFirst().orElseThrow(
                () -> new AssertionError("no field " + name + " in " + fieldsOf(request).stream()
                        .map(AuditInsertionPoint::name).toList()));
    }

    private static Map<String, String> mcpHeaders() {
        Map<String, String> headers = new LinkedHashMap<>();
        headers.put("Content-Type", "application/json");
        headers.put("Accept", "application/json, text/event-stream");
        headers.put("Mcp-Session-Id", "s-1");
        return headers;
    }
}
