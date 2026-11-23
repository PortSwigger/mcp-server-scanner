package com.mcpscanner.checks.shared.oauth;

import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Optional;

public record ClientCredentials(String clientId, Optional<ClientSecret> secret) {

    public static ClientCredentials publicClient(String clientId) {
        return new ClientCredentials(clientId, Optional.empty());
    }

    public Map<String, String> form(Map<String, String> parameters) {
        Map<String, String> form = new LinkedHashMap<>(parameters);
        if (basicSecret().isEmpty()) {
            form.put("client_id", clientId);
            secret.ifPresent(posted -> form.put("client_secret", posted.value()));
        }
        return form;
    }

    public Map<String, String> headers() {
        return basicSecret().map(basic -> Map.of("Authorization", "Basic " + Base64.getEncoder().encodeToString(
                        (formEncoded(clientId) + ":" + formEncoded(basic.value())).getBytes(StandardCharsets.UTF_8))))
                .orElse(Map.of());
    }

    private Optional<ClientSecret> basicSecret() {
        return secret.filter(issued -> issued.method() == ClientSecretMethod.BASIC);
    }

    private static String formEncoded(String value) {
        return URLEncoder.encode(value, StandardCharsets.UTF_8);
    }
}
