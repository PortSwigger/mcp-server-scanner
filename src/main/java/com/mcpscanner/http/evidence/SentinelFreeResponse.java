package com.mcpscanner.http.evidence;

import burp.api.montoya.core.ByteArray;
import burp.api.montoya.http.message.responses.HttpResponse;

import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Set;

final class SentinelFreeResponse {

    private final Set<String> sentinelHeaders;

    SentinelFreeResponse(Set<String> sentinelHeaders) {
        this.sentinelHeaders = sentinelHeaders;
    }

    HttpResponse of(HttpResponse response) {
        ByteArray bytes = response.toByteArray();
        if (bytes == null) {
            return response;
        }
        byte[] wire = bytes.getBytes();
        int headEnd = WireBytes.headEnd(wire);
        String head = new String(wire, 0, headEnd, StandardCharsets.ISO_8859_1);
        String kept = String.join("\r\n", Arrays.stream(head.split("\r\n", -1))
                .filter(line -> !isSentinel(line)).toList());
        if (kept.length() == head.length()) {
            return response;
        }
        ByteArrayOutputStream cleaned = new ByteArrayOutputStream();
        cleaned.writeBytes(kept.getBytes(StandardCharsets.ISO_8859_1));
        cleaned.write(wire, headEnd, wire.length - headEnd);
        return HttpResponse.httpResponse(ByteArray.byteArray(cleaned.toByteArray()));
    }

    private boolean isSentinel(String headerLine) {
        int colon = headerLine.indexOf(':');
        return colon > 0 && sentinelHeaders.contains(headerLine.substring(0, colon).trim());
    }
}
