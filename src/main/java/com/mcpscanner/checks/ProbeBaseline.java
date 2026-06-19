package com.mcpscanner.checks;

import burp.api.montoya.http.HttpService;
import burp.api.montoya.http.message.requests.HttpRequest;

import java.util.Optional;
import java.util.function.Supplier;

/**
 * Retargets a self-issued probe's baseline request at the local SSE proxy when the active transport
 * needs it. {@code Http.sendRequest} bypasses the registered {@code McpHttpHandler}, so without this
 * an SSE probe POSTs straight to the upstream {@code /messages} endpoint and reads the bare {@code
 * 202 Accepted} (the real reply rides the {@code /sse} stream). Swapping only the {@link HttpService}
 * — path and query are preserved, which the proxy's endpoint gate already accepts — routes the probe
 * through the proxy that lifts the reply. On Streamable HTTP the supplier is empty and the baseline
 * is returned unchanged.
 */
public final class ProbeBaseline {

    private ProbeBaseline() {}

    public static HttpRequest route(HttpRequest baseline, Supplier<Optional<HttpService>> probeService) {
        return probeService.get().map(baseline::withService).orElse(baseline);
    }
}
