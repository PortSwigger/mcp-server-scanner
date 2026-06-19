package com.mcpscanner.checks;

import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import com.mcpscanner.scan.ScanStartContext;

import java.util.Map;

/**
 * Builds a synthetic JSON-RPC {@code tools/call} baseline from a
 * {@link ScanStartContext}, used by scan-start checks that need a baseline
 * request shape but don't have a Burp-supplied {@link HttpRequestResponse}.
 *
 * <p>The synthetic request carries the connect-time headers (so the active
 * bearer token, if any, is attached) and points at the resolved MCP endpoint,
 * so downstream probe logic that mutates the baseline produces properly-targeted
 * on-wire requests.
 */
interface SessionBaselineFactory {

    String SYNTHETIC_BODY =
            "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/call\","
                    + "\"params\":{\"name\":\"scan-start\",\"arguments\":{}}}";

    HttpRequestResponse baselineFor(ScanStartContext context);

    static SessionBaselineFactory burpDefault() {
        return BurpHttpSessionBaselineFactory.INSTANCE;
    }
}

final class BurpHttpSessionBaselineFactory implements SessionBaselineFactory {

    static final BurpHttpSessionBaselineFactory INSTANCE = new BurpHttpSessionBaselineFactory();

    private static final String CONTENT_TYPE_HEADER = "Content-Type";
    private static final String ACCEPT_HEADER = "Accept";
    private static final String APPLICATION_JSON = "application/json";

    private BurpHttpSessionBaselineFactory() {
    }

    @Override
    public HttpRequestResponse baselineFor(ScanStartContext context) {
        HttpRequest request = HttpRequest.httpRequestFromUrl(context.endpoint())
                .withMethod("POST")
                .withBody(SYNTHETIC_BODY)
                .withAddedHeader(CONTENT_TYPE_HEADER, APPLICATION_JSON)
                .withAddedHeader(ACCEPT_HEADER, APPLICATION_JSON);
        for (Map.Entry<String, String> entry : context.headers().entrySet()) {
            request = request.withAddedHeader(entry.getKey(), entry.getValue());
        }
        return HttpRequestResponse.httpRequestResponse(request, null);
    }
}
