package com.mcpscanner.access.mining;

import com.fasterxml.jackson.databind.JsonNode;

import java.net.URI;
import java.util.regex.Pattern;

final class SecretValue {

    private static final Pattern JWT = Pattern.compile("eyJ[\\w-]+\\.[\\w-]+\\.[\\w-]*");
    private static final String SCHEME_SEPARATOR = "://";

    private SecretValue() {
    }

    static boolean matches(JsonNode value) {
        return value.isTextual() && matches(value.asText());
    }

    static boolean matches(String text) {
        return JWT.matcher(text).find() || carriesCredentialInUrl(text);
    }

    private static boolean carriesCredentialInUrl(String text) {
        if (!text.contains(SCHEME_SEPARATOR)) {
            return false;
        }
        try {
            URI url = URI.create(text.strip());
            return url.getRawUserInfo() != null || url.getRawQuery() != null || url.getRawFragment() != null;
        } catch (IllegalArgumentException unparseable) {
            return true;
        }
    }
}
