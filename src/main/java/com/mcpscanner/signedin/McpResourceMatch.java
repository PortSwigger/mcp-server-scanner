package com.mcpscanner.signedin;

import com.mcpscanner.mcp.HttpOrigin;

import java.net.URI;
import java.net.URISyntaxException;
import java.util.Objects;

final class McpResourceMatch {

    private McpResourceMatch() {
    }

    static boolean sameResource(URI resource, String endpoint) {
        try {
            URI connected = new URI(endpoint);
            return HttpOrigin.sameOrigin(resource, connected) && pathOf(resource).equals(pathOf(connected));
        } catch (URISyntaxException malformed) {
            return false;
        }
    }

    private static String pathOf(URI uri) {
        String path = Objects.requireNonNullElse(uri.getPath(), "");
        return path.endsWith("/") ? path.substring(0, path.length() - 1) : path;
    }
}
