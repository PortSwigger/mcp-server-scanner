package com.mcpscanner.auth.oauth.discovery;

import com.fasterxml.jackson.databind.JsonNode;
import com.mcpscanner.logging.McpEventLog;
import com.mcpscanner.mcp.McpObjectMapper;
import com.nimbusds.oauth2.sdk.as.AuthorizationServerMetadata;

import java.net.URI;
import java.util.Optional;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public final class MetadataParsers {

    private static final Pattern RESOURCE_METADATA_PATTERN =
            Pattern.compile("resource_metadata\\s*=\\s*\"([^\"]+)\"");

    private MetadataParsers() {}

    public static Optional<URI> parseResourceMetadataFromWwwAuthenticate(String headerValue) {
        if (headerValue == null) {
            return Optional.empty();
        }
        Matcher matcher = RESOURCE_METADATA_PATTERN.matcher(headerValue);
        if (!matcher.find()) {
            return Optional.empty();
        }
        try {
            return Optional.of(URI.create(matcher.group(1)));
        } catch (IllegalArgumentException e) {
            return Optional.empty();
        }
    }

    public static Optional<JsonNode> parseJsonObject(String json) {
        return parseJsonObject(json, null, null);
    }

    public static Optional<JsonNode> parseJsonObject(String json, McpEventLog eventLog, String context) {
        if (json == null || json.isBlank()) {
            return Optional.empty();
        }
        try {
            JsonNode node = McpObjectMapper.INSTANCE.readTree(json);
            return node.isObject() ? Optional.of(node) : Optional.empty();
        } catch (Exception e) {
            warn(eventLog, "Failed to parse JSON object"
                    + (context != null ? " from " + context : "")
                    + ": " + e.getMessage());
            return Optional.empty();
        }
    }

    public static Optional<AuthorizationServerMetadata> parseAs(String json) {
        return parseAs(json, null, null);
    }

    public static Optional<AuthorizationServerMetadata> parseAs(String json, McpEventLog eventLog, String context) {
        if (json == null || json.isBlank()) {
            return Optional.empty();
        }
        try {
            return Optional.of(AuthorizationServerMetadata.parse(json));
        } catch (Exception e) {
            warn(eventLog, "Failed to parse AS metadata"
                    + (context != null ? " from " + context : "")
                    + ": " + e.getMessage());
            return Optional.empty();
        }
    }

    private static void warn(McpEventLog eventLog, String message) {
        (eventLog != null ? eventLog : McpEventLog.noop()).warn(message);
    }
}
