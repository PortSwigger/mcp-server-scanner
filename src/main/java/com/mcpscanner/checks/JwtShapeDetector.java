package com.mcpscanner.checks;

import com.fasterxml.jackson.databind.JsonNode;
import com.mcpscanner.mcp.McpObjectMapper;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.Optional;
import java.util.regex.Pattern;

public final class JwtShapeDetector {

    public record JwtClaims(List<String> aud, Optional<String> iss) {
        public JwtClaims {
            aud = aud == null ? List.of() : List.copyOf(aud);
        }
    }

    private static final Pattern JWT_SHAPE =
            Pattern.compile("^[A-Za-z0-9_-]+\\.[A-Za-z0-9_-]+\\.[A-Za-z0-9_-]*$");

    private JwtShapeDetector() {}

    public static boolean isJwtShape(String token) {
        if (token == null || !JWT_SHAPE.matcher(token).matches()) {
            return false;
        }
        return decodeJsonObject(firstSegment(token))
                .map(header -> header.has("alg"))
                .orElse(false)
                && decodeJsonObject(payloadSegment(token)).isPresent();
    }

    public static Optional<JwtClaims> extractClaims(String token) {
        if (token == null || !JWT_SHAPE.matcher(token).matches()) {
            return Optional.empty();
        }
        return decodeJsonObject(payloadSegment(token))
                .map(payload -> new JwtClaims(extractAud(payload), extractIss(payload)));
    }

    private static Optional<JsonNode> decodeJsonObject(String segment) {
        try {
            byte[] decoded = Base64.getUrlDecoder().decode(padBase64Url(segment));
            JsonNode node = McpObjectMapper.INSTANCE.readTree(new String(decoded, StandardCharsets.UTF_8));
            return node.isObject() ? Optional.of(node) : Optional.empty();
        } catch (Exception ignored) {
            return Optional.empty();
        }
    }

    private static String padBase64Url(String segment) {
        int remainder = segment.length() % 4;
        return remainder == 0 ? segment : segment + "=".repeat(4 - remainder);
    }

    private static String firstSegment(String token) {
        return token.substring(0, token.indexOf('.'));
    }

    private static String payloadSegment(String token) {
        int firstDot = token.indexOf('.');
        int secondDot = token.indexOf('.', firstDot + 1);
        return token.substring(firstDot + 1, secondDot);
    }

    private static List<String> extractAud(JsonNode payload) {
        JsonNode aud = payload.path("aud");
        if (aud.isTextual()) {
            return List.of(aud.asText());
        }
        if (aud.isArray()) {
            List<String> values = new ArrayList<>();
            for (JsonNode element : aud) {
                if (element.isTextual()) {
                    values.add(element.asText());
                }
            }
            return List.copyOf(values);
        }
        return List.of();
    }

    private static Optional<String> extractIss(JsonNode payload) {
        JsonNode iss = payload.path("iss");
        return iss.isTextual() ? Optional.of(iss.asText()) : Optional.empty();
    }
}
