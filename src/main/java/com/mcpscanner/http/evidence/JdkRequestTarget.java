package com.mcpscanner.http.evidence;

import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.text.Normalizer;
import java.util.HexFormat;

final class JdkRequestTarget {

    private static final HexFormat UPPER_HEX = HexFormat.of().withUpperCase();

    private JdkRequestTarget() {
    }

    static String of(URI uri) {
        String path = uri.getRawPath() == null || uri.getRawPath().isEmpty() ? "/" : uri.getRawPath();
        String query = uri.getRawQuery();
        return asciiOnly(query == null || query.isEmpty() ? path : path + "?" + query);
    }

    private static String asciiOnly(String target) {
        if (target.chars().allMatch(character -> character < 0x80)) {
            return target;
        }
        StringBuilder encoded = new StringBuilder();
        for (byte octet : Normalizer.normalize(target, Normalizer.Form.NFC).getBytes(StandardCharsets.UTF_8)) {
            appendOctet(encoded, octet);
        }
        return encoded.toString();
    }

    private static void appendOctet(StringBuilder encoded, byte octet) {
        if ((octet & 0xff) >= 0x80) {
            encoded.append('%').append(UPPER_HEX.toHexDigits(octet));
        } else {
            encoded.append((char) octet);
        }
    }
}
