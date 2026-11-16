package com.mcpscanner.checks.registry;

import burp.api.montoya.core.ByteArray;
import burp.api.montoya.http.message.responses.HttpResponse;
import com.mcpscanner.mcp.ScannerSentinels;

import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;

final class SentinelFreeResponse {

    private static final byte[] HEAD_END = "\r\n\r\n".getBytes(StandardCharsets.ISO_8859_1);

    private SentinelFreeResponse() {
    }

    static HttpResponse of(HttpResponse response) {
        ByteArray bytes = response.toByteArray();
        if (bytes == null) {
            return response;
        }
        byte[] wire = bytes.getBytes();
        int headEnd = indexOfHeadEnd(wire);
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

    private static boolean isSentinel(String headerLine) {
        int colon = headerLine.indexOf(':');
        return colon > 0 && ScannerSentinels.ALL.contains(headerLine.substring(0, colon).trim());
    }

    private static int indexOfHeadEnd(byte[] wire) {
        for (int index = 0; index + HEAD_END.length <= wire.length; index++) {
            if (Arrays.equals(wire, index, index + HEAD_END.length, HEAD_END, 0, HEAD_END.length)) {
                return index;
            }
        }
        return wire.length;
    }
}
