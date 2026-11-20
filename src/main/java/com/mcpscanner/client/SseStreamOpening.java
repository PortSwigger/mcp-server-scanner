package com.mcpscanner.client;

import burp.api.montoya.http.message.HttpRequestResponse;
import com.mcpscanner.http.evidence.LegacySseExchange;
import com.mcpscanner.http.evidence.WireRecord;
import com.mcpscanner.mcp.RawSseFrame;

import java.net.http.HttpResponse;
import java.util.List;

final class SseStreamOpening {

    private final HttpResponse<?> stream;

    SseStreamOpening(HttpResponse<?> stream) {
        this.stream = stream;
    }

    List<HttpRequestResponse> evidenceOf(WireRecord post, RawSseFrame frame) {
        return LegacySseExchange.answered(post, stream, frame.bytes()).stream().map(WireRecord::evidence).toList();
    }
}
