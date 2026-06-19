package com.mcpscanner.mcp;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.StringReader;
import java.net.URI;
import java.net.URISyntaxException;

import com.fasterxml.jackson.databind.JsonNode;

public final class SseResponseParser {

    private static final int MAX_EVENT_BYTES = 1024 * 1024;
    private static final int MAX_ENDPOINT_SCAN_BYTES = 256 * 1024;

    private SseResponseParser() {}

    public record SseEvent(String eventType, String data) {}

    public static SseEvent readNextEvent(BufferedReader reader) throws IOException {
        String eventType = null;
        StringBuilder data = null;
        String line;
        while ((line = readBoundedLine(reader)) != null) {
            if (line.startsWith("event: ")) {
                eventType = line.substring(7).trim();
            } else if (line.startsWith("data: ")) {
                String content = line.substring(6);
                if (data == null) {
                    data = new StringBuilder(content);
                } else {
                    data.append('\n').append(content);
                }
                if (data.length() > MAX_EVENT_BYTES) {
                    throw new IOException("SSE event data exceeded " + MAX_EVENT_BYTES + " bytes");
                }
            } else if (line.isEmpty() && data != null) {
                return new SseEvent(eventType, data.toString());
            }
        }
        return null;
    }

    private static String readBoundedLine(BufferedReader reader) throws IOException {
        StringBuilder line = new StringBuilder();
        int read;
        while ((read = reader.read()) != -1) {
            char c = (char) read;
            if (c == '\n') {
                return line.toString();
            }
            if (c == '\r') {
                continue;
            }
            line.append(c);
            if (line.length() > MAX_EVENT_BYTES) {
                throw new IOException("SSE line exceeded " + MAX_EVENT_BYTES + " bytes");
            }
        }
        return line.length() == 0 ? null : line.toString();
    }

    public static String extractJsonRpcResponse(String sseBody) {
        if (sseBody == null || sseBody.isEmpty()) {
            return null;
        }
        try {
            return extractJsonRpcResponse(new BufferedReader(new StringReader(sseBody)));
        } catch (IOException e) {
            return null;
        }
    }

    public static String extractJsonRpcResponse(BufferedReader reader) throws IOException {
        String lastData = null;
        String currentEventType = null;
        StringBuilder currentData = null;

        String line;
        while ((line = readBoundedLine(reader)) != null) {
            if (line.startsWith("event: ")) {
                currentEventType = line.substring(7).trim();
                currentData = null;
            } else if (line.startsWith("data: ") && isMessageEvent(currentEventType)) {
                String dataContent = line.substring(6);
                if (currentData == null) {
                    currentData = new StringBuilder(dataContent);
                } else {
                    currentData.append("\n").append(dataContent);
                }
                if (currentData.length() > MAX_EVENT_BYTES) {
                    throw new IOException("SSE event data exceeded " + MAX_EVENT_BYTES + " bytes");
                }
            } else if (line.isEmpty()) {
                if (currentData != null) {
                    String data = currentData.toString();
                    if (hasTopLevelId(data)) {
                        return data;
                    }
                    lastData = data;
                    currentData = null;
                }
                currentEventType = null;
            }
        }

        if (currentData != null) {
            String data = currentData.toString();
            if (hasTopLevelId(data)) {
                return data;
            }
            lastData = data;
        }

        return lastData;
    }

    private static boolean isMessageEvent(String eventType) {
        return eventType == null || "message".equals(eventType);
    }

    public static String extractEndpointUrl(BufferedReader reader) throws IOException {
        String eventType = null;
        String line;
        int totalScanned = 0;
        while ((line = readBoundedLine(reader)) != null) {
            totalScanned += line.length() + 1;
            if (totalScanned > MAX_ENDPOINT_SCAN_BYTES) {
                throw new IOException("Endpoint event scan exceeded " + MAX_ENDPOINT_SCAN_BYTES + " bytes");
            }
            if (line.startsWith("event: ")) {
                eventType = line.substring(7).trim();
            } else if (line.startsWith("data: ") && "endpoint".equals(eventType)) {
                return line.substring(6).trim();
            }
        }
        return null;
    }

    public static String resolveMessageUrl(String sseUrl, String endpointPath) {
        if (sseUrl == null || endpointPath == null) {
            return null;
        }
        URI base;
        URI resolved;
        try {
            base = new URI(sseUrl);
            resolved = base.resolve(endpointPath);
        } catch (URISyntaxException | IllegalArgumentException e) {
            return null;
        }
        if (!sameOrigin(base, resolved)) {
            return null;
        }
        return resolved.toString();
    }

    private static boolean sameOrigin(URI base, URI resolved) {
        if (resolved.getScheme() == null || resolved.getHost() == null) {
            return false;
        }
        if (!resolved.getScheme().equalsIgnoreCase(base.getScheme())) {
            return false;
        }
        if (!resolved.getHost().equalsIgnoreCase(base.getHost())) {
            return false;
        }
        return effectivePort(base) == effectivePort(resolved);
    }

    private static int effectivePort(URI uri) {
        int port = uri.getPort();
        if (port != -1) {
            return port;
        }
        return "https".equalsIgnoreCase(uri.getScheme()) ? 443 : 80;
    }

    private static boolean hasTopLevelId(String json) {
        try {
            JsonNode node = McpObjectMapper.INSTANCE.readTree(json);
            return node != null && node.has("id");
        } catch (Exception e) {
            return false;
        }
    }
}
