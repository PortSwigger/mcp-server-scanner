package com.mcpscanner.checks.content;

import burp.api.montoya.http.message.HttpRequestResponse;
import com.fasterxml.jackson.databind.JsonNode;
import com.mcpscanner.mcp.McpObjectMapper;
import com.mcpscanner.mcp.McpRequestDetector;
import com.mcpscanner.mcp.McpRequestDetector.ResponseContentKind;

import java.util.ArrayList;
import java.util.List;

/**
 * Translates an MCP runtime-output JSON-RPC response ({@code tools/call},
 * {@code resources/read}, {@code prompts/get}) into the spec-defined textual
 * {@link InspectedField}s the {@link ContentRuleEngine} runs secret rules against.
 *
 * <p>Sibling to {@link JsonRpcDiscoveredContentTranslator}, but scoped to response bodies
 * rather than discovery metadata. SSE-framed responses are unwrapped via
 * {@link McpRequestDetector#jsonRpcBody}. Only text-bearing fields are emitted —
 * {@code resources/read} {@code blob} entries and non-text {@code content} items are
 * skipped. Total extracted text is capped at {@link #MAX_EXTRACTED_BYTES} to bound the work
 * Burp's passive thread does on a hostile or runaway response.
 */
public final class ResponseBodyContentExtractor {

    private static final int MAX_EXTRACTED_BYTES = 512 * 1024;

    private ResponseBodyContentExtractor() {}

    public static List<InspectedField> extract(ResponseContentKind kind, HttpRequestResponse rr) {
        if (kind == null || kind == ResponseContentKind.OTHER || rr == null) {
            return List.of();
        }
        JsonNode result = parseResult(rr);
        if (result == null) {
            return List.of();
        }
        JsonNode params = parseRequestParams(rr);
        return switch (kind) {
            case TOOL_CALL -> toolCallFields(result, textOrEmpty(params, "name"));
            case RESOURCE_READ -> resourceReadFields(result, textOrEmpty(params, "uri"));
            case PROMPT_GET -> promptGetFields(result, textOrEmpty(params, "name"));
            default -> List.of();
        };
    }

    private static List<InspectedField> toolCallFields(JsonNode result, String toolName) {
        Collector collector = new Collector(SourceObjectType.TOOL, toolName);
        JsonNode content = result.path("content");
        int index = 0;
        for (JsonNode item : content) {
            if (collector.exhausted()) {
                break;
            }
            String prefix = "content[" + index + "]";
            if (isTextItem(item)) {
                collector.add(prefix + ".text", item.path("text"));
            }
            JsonNode embeddedText = item.path("resource").path("text");
            collector.add(prefix + ".resource.text", embeddedText);
            index++;
        }
        return collector.fields();
    }

    private static List<InspectedField> resourceReadFields(JsonNode result, String uri) {
        Collector collector = new Collector(SourceObjectType.RESOURCE, uri);
        JsonNode contents = result.path("contents");
        int index = 0;
        for (JsonNode item : contents) {
            if (collector.exhausted()) {
                break;
            }
            collector.add("contents[" + index + "].text", item.path("text"));
            index++;
        }
        return collector.fields();
    }

    private static List<InspectedField> promptGetFields(JsonNode result, String promptName) {
        Collector collector = new Collector(SourceObjectType.PROMPT, promptName);
        JsonNode messages = result.path("messages");
        int index = 0;
        for (JsonNode message : messages) {
            if (collector.exhausted()) {
                break;
            }
            collector.add("messages[" + index + "].content.text",
                    message.path("content").path("text"));
            index++;
        }
        return collector.fields();
    }

    private static boolean isTextItem(JsonNode item) {
        return "text".equals(textOrEmpty(item, "type"));
    }

    private static JsonNode parseResult(HttpRequestResponse rr) {
        if (rr.response() == null) {
            return null;
        }
        try {
            JsonNode root = McpObjectMapper.INSTANCE.readTree(
                    McpRequestDetector.jsonRpcBody(rr.response()));
            JsonNode result = root.path("result");
            return result.isObject() ? result : null;
        } catch (Exception ignored) {
            return null;
        }
    }

    private static JsonNode parseRequestParams(HttpRequestResponse rr) {
        try {
            return McpObjectMapper.INSTANCE.readTree(rr.request().bodyToString()).path("params");
        } catch (Exception ignored) {
            return McpObjectMapper.INSTANCE.missingNode();
        }
    }

    private static String textOrEmpty(JsonNode parent, String field) {
        JsonNode node = parent.path(field);
        return node.isTextual() ? node.asText() : "";
    }

    private static final class Collector {

        private final SourceObjectType objectType;
        private final String objectName;
        private final List<InspectedField> fields = new ArrayList<>();
        private int budget = MAX_EXTRACTED_BYTES;

        private Collector(SourceObjectType objectType, String objectName) {
            this.objectType = objectType;
            this.objectName = objectName;
        }

        private void add(String fieldPath, JsonNode textNode) {
            if (budget <= 0 || !textNode.isTextual()) {
                return;
            }
            String text = textNode.asText();
            if (text.isEmpty()) {
                return;
            }
            String capped = text.length() <= budget ? text : text.substring(0, budget);
            budget -= capped.length();
            fields.add(new InspectedField(objectType, objectName, fieldPath, capped));
        }

        private boolean exhausted() {
            return budget <= 0;
        }

        private List<InspectedField> fields() {
            return List.copyOf(fields);
        }
    }
}
