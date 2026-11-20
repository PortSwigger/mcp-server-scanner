package com.mcpscanner.proxy;

import burp.api.montoya.http.message.HttpRequestResponse;
import com.mcpscanner.http.evidence.LegacySseExchange;
import com.mcpscanner.http.evidence.WireRecord;

import java.util.List;

record RecordedExchange(String requestBody, List<WireRecord> wires) {

    RecordedExchange(String requestBody, WireRecord wire) {
        this(requestBody, List.of(wire));
    }

    long bodyBytes() {
        return wires.stream().mapToLong(WireRecord::size).sum();
    }

    List<HttpRequestResponse> evidence() {
        return wires.stream().map(WireRecord::evidence).toList();
    }

    RecordedExchange answeredOnStream(java.net.http.HttpResponse<?> stream, byte[] event) {
        return new RecordedExchange(requestBody, LegacySseExchange.answered(wires.get(0), stream, event));
    }
}
