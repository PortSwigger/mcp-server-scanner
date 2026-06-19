package com.mcpscanner.checks;

import com.fasterxml.jackson.databind.JsonNode;
import com.mcpscanner.mcp.McpObjectMapper;
import com.mcpscanner.mcp.McpRequestDetector;

import java.util.ArrayList;
import java.util.List;

/**
 * Lifts the human-readable text out of a {@code tools/call} reply. Both the success-signature
 * oracle (in-band {@code result.content[*].text}) and the error-differential oracle (tool-error
 * {@code result.content[*].text} or a JSON-RPC {@code error.message}) read the same fields, so the
 * extraction lives here once.
 */
final class ToolCallTextExtractor {

    private ToolCallTextExtractor() {}

    /** {@code result.content[*].text} regardless of {@code isError}, plus any JSON-RPC
     *  {@code error.message}. server-filesystem reports access/ENOENT failures as a tool-error
     *  envelope ({@code isError:true} with the message in {@code content}), so the error oracle
     *  must read content text, not just the JSON-RPC error object. */
    static List<String> allText(com.fasterxml.jackson.databind.JsonNode root) {
        List<String> texts = new ArrayList<>();
        JsonNode content = root.path("result").path("content");
        if (content.isArray()) {
            for (JsonNode entry : content) {
                if (entry.path("text").isTextual()) {
                    texts.add(entry.path("text").asText());
                }
            }
        }
        JsonNode errorMessage = root.path("error").path("message");
        if (errorMessage.isTextual()) {
            texts.add(errorMessage.asText());
        }
        return texts;
    }

    static List<String> contentText(String body) {
        try {
            JsonNode content = McpObjectMapper.INSTANCE.readTree(body).path("result").path("content");
            if (!content.isArray()) {
                return List.of();
            }
            List<String> texts = new ArrayList<>(content.size());
            for (JsonNode entry : content) {
                if (entry.path("text").isTextual()) {
                    texts.add(entry.path("text").asText());
                }
            }
            return texts;
        } catch (Exception ignored) {
            return List.of();
        }
    }

    static List<String> allTextFromResponse(burp.api.montoya.http.message.HttpRequestResponse response) {
        if (response.response() == null) {
            return List.of();
        }
        String body = McpRequestDetector.jsonRpcBody(response.response());
        if (body == null || body.isEmpty()) {
            return List.of();
        }
        try {
            return allText(McpObjectMapper.INSTANCE.readTree(body));
        } catch (Exception ignored) {
            return List.of();
        }
    }
}
