package com.mcpscanner.client;

import com.mcpscanner.logging.McpEventLog;

import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.util.Objects;

public final class RedirectLoggingInterceptor {

    private final McpEventLog eventLog;

    public RedirectLoggingInterceptor(McpEventLog eventLog) {
        this.eventLog = eventLog;
    }

    public <T> HttpResponse<T> sendAndLog(HttpClient client, HttpRequest request,
                                          HttpResponse.BodyHandler<T> bodyHandler)
            throws IOException, InterruptedException {
        HttpResponse<T> response = client.send(request, bodyHandler);
        warnIfCrossOrigin(request.uri(), response.uri());
        return response;
    }

    private void warnIfCrossOrigin(URI sent, URI received) {
        if (isCrossOrigin(sent, received)) {
            eventLog.warn("Cross-origin redirect followed: " + sent + " -> " + received);
        }
    }

    private static boolean isCrossOrigin(URI sent, URI received) {
        if (received == null) {
            return false;
        }
        return !Objects.equals(sent.getHost(), received.getHost())
                || normalizedPort(sent) != normalizedPort(received)
                || !Objects.equals(sent.getScheme(), received.getScheme());
    }

    private static int normalizedPort(URI uri) {
        int port = uri.getPort();
        if (port != -1) return port;
        String scheme = uri.getScheme();
        if ("https".equalsIgnoreCase(scheme)) return 443;
        if ("http".equalsIgnoreCase(scheme)) return 80;
        return -1;
    }
}
