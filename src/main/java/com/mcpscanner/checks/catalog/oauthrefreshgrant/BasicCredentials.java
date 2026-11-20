package com.mcpscanner.checks.catalog.oauthrefreshgrant;

import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.Base64;

final class BasicCredentials {

    static final String AUTHORIZATION = "Authorization";
    static final String PREFIX = "Basic ";

    private BasicCredentials() {
    }

    private static String encoded(String clientId, String secret) {
        String pair = formEncode(clientId) + ":" + formEncode(secret);
        return Base64.getEncoder().encodeToString(pair.getBytes(StandardCharsets.UTF_8));
    }

    static String header(String clientId, String secret) {
        return PREFIX + encoded(clientId, secret);
    }

    static String formEncode(String value) {
        return URLEncoder.encode(value, StandardCharsets.UTF_8);
    }
}
