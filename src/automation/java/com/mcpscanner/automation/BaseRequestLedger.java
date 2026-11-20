package com.mcpscanner.automation;

import burp.api.montoya.http.message.requests.HttpRequest;
import com.mcpscanner.mcp.ScannerSentinels;
import com.mcpscanner.scan.request.ClientRegistrationMessage;
import com.mcpscanner.scan.request.McpMessage;
import com.mcpscanner.scan.request.ScanMessageRenderer;

import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.stream.Collectors;

public final class BaseRequestLedger {

    private static final Set<String> MANAGED_IN_FLIGHT = Set.of("host", "content-length", "connection",
            ScannerSentinels.ROUTED_HEADER.toLowerCase(Locale.ROOT),
            ScannerSentinels.GENERATED_REGISTRATION_HEADER.toLowerCase(Locale.ROOT));

    private final Set<String> launched = ConcurrentHashMap.newKeySet();

    public ScanMessageRenderer recording(ScanMessageRenderer renderer) {
        return new ScanMessageRenderer() {
            @Override
            public HttpRequest renderJsonRpc(String mcpEndpoint, McpMessage message, Map<String, String> headers) {
                return recorded(renderer.renderJsonRpc(mcpEndpoint, message, headers));
            }

            @Override
            public HttpRequest renderClientRegistration(ClientRegistrationMessage message) {
                return recorded(renderer.renderClientRegistration(message));
            }
        };
    }

    boolean contains(HttpRequest request) {
        return launched.contains(keyOf(request));
    }

    void clear() {
        launched.clear();
    }

    private HttpRequest recorded(HttpRequest rendered) {
        launched.add(keyOf(rendered));
        return rendered;
    }

    private static String keyOf(HttpRequest request) {
        return request.method() + " " + request.path() + "\n" + identifyingHeaders(request) + "\n"
                + request.bodyToString();
    }

    private static String identifyingHeaders(HttpRequest request) {
        return request.headers().stream()
                .filter(header -> identifying(header.name()))
                .map(header -> header.name().toLowerCase(Locale.ROOT) + ":" + header.value().strip())
                .sorted()
                .collect(Collectors.joining("\n"));
    }

    private static boolean identifying(String headerName) {
        return !MANAGED_IN_FLIGHT.contains(headerName.toLowerCase(Locale.ROOT));
    }
}
