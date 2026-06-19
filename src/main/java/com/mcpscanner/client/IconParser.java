package com.mcpscanner.client;

import com.fasterxml.jackson.databind.JsonNode;
import com.mcpscanner.mcp.IconDescriptor;

import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Pure parser that extracts {@link IconDescriptor}s from the JSON-RPC envelopes
 * returned by {@code tools/list}, {@code resources/list}, and {@code prompts/list}
 * MCP responses (spec revision 2025-11-25).
 *
 * <p>The envelopes are sourced from {@link CapturingMcpTransport}, which stashes
 * the {@link JsonNode} returned by langchain4j-mcp's transport on each list call.
 * Going through the transport is the only correct path because SSE servers reply
 * 202-empty to direct POSTs — a raw HTTP probe would silently drop icons over SSE.
 */
final class IconParser {

    private IconParser() {}

    /**
     * Walks the {@code result.<arrayKey>} list inside the envelope and returns the icons
     * keyed by each entry's {@code name}. Entries without a {@code name} or without any
     * {@code icons} array are skipped — the caller decides how to merge what remains.
     */
    static Map<String, List<IconDescriptor>> parseIcons(JsonNode envelope, String arrayKey) {
        if (envelope == null) {
            return Collections.emptyMap();
        }
        JsonNode array = envelope.path("result").path(arrayKey);
        if (!array.isArray()) {
            return Collections.emptyMap();
        }
        Map<String, List<IconDescriptor>> byName = new LinkedHashMap<>();
        for (JsonNode entry : array) {
            String name = entry.path("name").asText(null);
            if (name == null) {
                continue;
            }
            List<IconDescriptor> icons = readIcons(entry.path("icons"));
            if (!icons.isEmpty()) {
                byName.put(name, icons);
            }
        }
        return byName;
    }

    /**
     * Extracts the server-level (Implementation) icons from the {@code initialize}
     * envelope's {@code result.serverInfo.icons} array (MCP spec SEP-973). Returns an
     * empty list when the field is absent — the common case for servers that ship no
     * server-level icon.
     */
    static List<IconDescriptor> parseServerIcons(JsonNode envelope) {
        if (envelope == null) {
            return List.of();
        }
        return readIcons(envelope.path("result").path("serverInfo").path("icons"));
    }

    private static List<IconDescriptor> readIcons(JsonNode iconsNode) {
        if (!iconsNode.isArray()) {
            return List.of();
        }
        List<IconDescriptor> icons = new ArrayList<>(iconsNode.size());
        for (JsonNode icon : iconsNode) {
            icons.add(toDescriptor(icon));
        }
        return icons;
    }

    private static IconDescriptor toDescriptor(JsonNode icon) {
        return new IconDescriptor(
                textOrNull(icon.path("src")),
                textOrNull(icon.path("mimeType")),
                readSizes(icon.path("sizes")));
    }

    private static List<String> readSizes(JsonNode sizesNode) {
        if (!sizesNode.isArray()) {
            return List.of();
        }
        List<String> sizes = new ArrayList<>(sizesNode.size());
        for (JsonNode size : sizesNode) {
            if (size.isTextual()) {
                sizes.add(size.asText());
            }
        }
        return sizes;
    }

    private static String textOrNull(JsonNode node) {
        return node.isTextual() ? node.asText() : null;
    }
}
