package com.mcpscanner.client;

import burp.api.montoya.logging.Logging;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.mcpscanner.logging.McpEventLog;
import com.mcpscanner.mcp.IconDescriptor;
import com.mcpscanner.mcp.McpObjectMapper;
import com.mcpscanner.mcp.McpPromptDefinition;
import com.mcpscanner.mcp.McpResourceDefinition;
import com.mcpscanner.mcp.McpResourceTemplateDefinition;
import com.mcpscanner.mcp.McpToolDefinition;
import com.mcpscanner.mcp.PromptArgument;
import com.mcpscanner.mcp.ServerMetadata;
import com.mcpscanner.mcp.ToolAnnotations;
import dev.langchain4j.agent.tool.ToolSpecification;
import dev.langchain4j.mcp.client.McpClient;
import dev.langchain4j.mcp.client.McpPrompt;
import dev.langchain4j.mcp.client.McpPromptArgument;
import dev.langchain4j.mcp.client.McpResource;
import dev.langchain4j.mcp.client.McpResourceTemplate;
import dev.langchain4j.mcp.client.McpToolMetadataKeys;
import dev.langchain4j.model.chat.request.json.JsonAnyOfSchema;
import dev.langchain4j.model.chat.request.json.JsonArraySchema;
import dev.langchain4j.model.chat.request.json.JsonBooleanSchema;
import dev.langchain4j.model.chat.request.json.JsonEnumSchema;
import dev.langchain4j.model.chat.request.json.JsonIntegerSchema;
import dev.langchain4j.model.chat.request.json.JsonNumberSchema;
import dev.langchain4j.model.chat.request.json.JsonObjectSchema;
import dev.langchain4j.model.chat.request.json.JsonReferenceSchema;
import dev.langchain4j.model.chat.request.json.JsonSchemaElement;
import dev.langchain4j.model.chat.request.json.JsonStringSchema;

import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.function.Function;
import java.util.function.Supplier;

public class McpDiscoveryClient {

    private static final Map<Class<? extends JsonSchemaElement>,
            Function<JsonSchemaElement, Map<String, Object>>> SCHEMA_CONVERTERS = buildSchemaConverters();
    private static final Function<JsonSchemaElement, Map<String, Object>> UNKNOWN_SCHEMA_HANDLER =
            element -> new LinkedHashMap<>();

    private final McpClient client;
    private final Logging logging;
    private final McpEventLog eventLog;
    private final ObjectMapper objectMapper;

    public McpDiscoveryClient(McpClient client, Logging logging) {
        this(client, logging, McpEventLog.noop(), McpObjectMapper.INSTANCE);
    }

    public McpDiscoveryClient(McpClient client, Logging logging, McpEventLog eventLog) {
        this(client, logging, eventLog, McpObjectMapper.INSTANCE);
    }

    McpDiscoveryClient(McpClient client, Logging logging, ObjectMapper objectMapper) {
        this(client, logging, McpEventLog.noop(), objectMapper);
    }

    McpDiscoveryClient(McpClient client, Logging logging, McpEventLog eventLog, ObjectMapper objectMapper) {
        this.client = client;
        this.logging = logging;
        this.eventLog = eventLog != null ? eventLog : McpEventLog.noop();
        this.objectMapper = objectMapper;
    }

    public List<McpToolDefinition> discoverTools() {
        return client.listTools().stream()
                .map(this::toToolDefinition)
                .toList();
    }

    public List<McpResourceDefinition> discoverResources() {
        try {
            return client.listResources().stream()
                    .map(McpDiscoveryClient::toResourceDefinition)
                    .toList();
        }
        // listResources can throw for any non-resources server; swallow so tools-only connects still succeed.
        catch (Exception e) {
            logging.logToOutput("MCP server does not advertise resources: " + e.getMessage());
            eventLog.info("Server does not advertise resources");
            return Collections.emptyList();
        }
    }

    public List<McpResourceTemplateDefinition> discoverResourceTemplates() {
        try {
            return client.listResourceTemplates().stream()
                    .map(McpDiscoveryClient::toResourceTemplateDefinition)
                    .toList();
        }
        // listResourceTemplates can throw for any non-resource templates server; swallow so tools-only connects still succeed.
        catch (Exception e) {
            logging.logToOutput("MCP server does not advertise resource templates: " + e.getMessage());
            eventLog.info("Server does not advertise resource templates");
            return Collections.emptyList();
        }
    }

    public List<McpPromptDefinition> discoverPrompts() {
        try {
            return client.listPrompts().stream()
                    .map(McpDiscoveryClient::toPromptDefinition)
                    .toList();
        }
        // listPrompts can throw for any non-prompts server; swallow so tools-only connects still succeed.
        catch (Exception e) {
            logging.logToOutput("MCP server does not advertise prompts: " + e.getMessage());
            eventLog.info("Server does not advertise prompts");
            return Collections.emptyList();
        }
    }

    /**
     * Discovers tools, then merges icons parsed from the {@code tools/list} envelope
     * supplied by {@code capturedEnvelope.get()}. The supplier is invoked <em>after</em>
     * discovery so that the captor (typically {@link CapturingMcpTransport}) has been
     * driven by the underlying {@code listTools()} call. Icons are matched on the
     * tool's {@code name} field.
     */
    public List<McpToolDefinition> discoverToolsWithIcons(Supplier<JsonNode> capturedEnvelope) {
        List<McpToolDefinition> tools = discoverTools();
        return mergeToolIcons(tools, capturedEnvelope.get());
    }

    public List<McpResourceDefinition> discoverResourcesWithIcons(Supplier<JsonNode> capturedEnvelope) {
        List<McpResourceDefinition> resources = discoverResources();
        return mergeResourceIcons(resources, capturedEnvelope.get());
    }

    public List<McpPromptDefinition> discoverPromptsWithIcons(Supplier<JsonNode> capturedEnvelope) {
        List<McpPromptDefinition> prompts = discoverPrompts();
        return mergePromptIcons(prompts, capturedEnvelope.get());
    }

    private static List<McpToolDefinition> mergeToolIcons(List<McpToolDefinition> tools,
                                                          JsonNode envelope) {
        Map<String, List<IconDescriptor>> iconsByName = IconParser.parseIcons(envelope, "tools");
        if (tools.isEmpty() || iconsByName.isEmpty()) {
            return tools;
        }
        List<McpToolDefinition> merged = new ArrayList<>(tools.size());
        for (McpToolDefinition tool : tools) {
            List<IconDescriptor> icons = iconsByName.get(tool.name());
            merged.add(icons == null
                    ? tool
                    : new McpToolDefinition(tool.name(), tool.description(), tool.inputSchema(),
                            icons, tool.annotations()));
        }
        return List.copyOf(merged);
    }

    private static List<McpResourceDefinition> mergeResourceIcons(List<McpResourceDefinition> resources,
                                                                  JsonNode envelope) {
        Map<String, List<IconDescriptor>> iconsByName = IconParser.parseIcons(envelope, "resources");
        if (resources.isEmpty() || iconsByName.isEmpty()) {
            return resources;
        }
        List<McpResourceDefinition> merged = new ArrayList<>(resources.size());
        for (McpResourceDefinition resource : resources) {
            List<IconDescriptor> icons = iconsByName.get(resource.name());
            merged.add(icons == null
                    ? resource
                    : new McpResourceDefinition(
                            resource.uri(), resource.name(), resource.description(),
                            resource.mimeType(), icons));
        }
        return List.copyOf(merged);
    }

    private static List<McpPromptDefinition> mergePromptIcons(List<McpPromptDefinition> prompts,
                                                              JsonNode envelope) {
        Map<String, List<IconDescriptor>> iconsByName = IconParser.parseIcons(envelope, "prompts");
        if (prompts.isEmpty() || iconsByName.isEmpty()) {
            return prompts;
        }
        List<McpPromptDefinition> merged = new ArrayList<>(prompts.size());
        for (McpPromptDefinition prompt : prompts) {
            List<IconDescriptor> icons = iconsByName.get(prompt.name());
            merged.add(icons == null
                    ? prompt
                    : new McpPromptDefinition(
                            prompt.name(), prompt.description(), prompt.arguments(), icons));
        }
        return List.copyOf(merged);
    }

    /**
     * Builds {@link ServerMetadata} from the JSON-RPC envelope returned by
     * {@code McpTransport.initialize(...)}. Langchain4j-mcp's transport calls
     * {@code initialize} during {@code DefaultMcpClient} setup and yields the
     * full envelope ({@code {"jsonrpc","id","result":{serverInfo,instructions,
     * capabilities,...}}}) regardless of whether the wire carrier was Streamable
     * HTTP (inline JSON body) or SSE (delivered over the open event stream).
     * Reading the captured envelope keeps server-info / instructions / capabilities
     * correct on both transports — a hand-rolled probe to the resolved endpoint
     * silently returns 202-empty on SSE and drops every field.
     */
    public ServerMetadata fetchServerMetadata(JsonNode initializeEnvelope) {
        if (initializeEnvelope == null) {
            return ServerMetadata.empty();
        }
        try {
            String envelopeJson = objectMapper.writeValueAsString(initializeEnvelope);
            return new ServerMetadata(
                    InitializeResponseParser.parseServerInfo(envelopeJson, eventLog),
                    InitializeResponseParser.parseInstructions(envelopeJson, eventLog),
                    InitializeResponseParser.parseCapabilities(envelopeJson, eventLog),
                    IconParser.parseServerIcons(initializeEnvelope));
        } catch (Exception e) {
            logging.logToOutput("Server metadata parse skipped: " + e.getClass().getSimpleName());
            eventLog.warn("Server metadata parse skipped: " + e.getClass().getSimpleName());
            return ServerMetadata.empty();
        }
    }

    public void close() throws Exception {
        client.close();
    }

    private McpToolDefinition toToolDefinition(ToolSpecification spec) {
        return new McpToolDefinition(
                spec.name(),
                spec.description(),
                serializeToolParameters(spec),
                List.of(),
                toAnnotations(spec.metadata()));
    }

    private static ToolAnnotations toAnnotations(Map<String, Object> metadata) {
        if (metadata == null || metadata.isEmpty()) {
            return ToolAnnotations.EMPTY;
        }
        return new ToolAnnotations(
                stringMetadata(metadata, McpToolMetadataKeys.TITLE_ANNOTATION),
                booleanMetadata(metadata, McpToolMetadataKeys.READ_ONLY_HINT),
                booleanMetadata(metadata, McpToolMetadataKeys.DESTRUCTIVE_HINT),
                booleanMetadata(metadata, McpToolMetadataKeys.IDEMPOTENT_HINT),
                booleanMetadata(metadata, McpToolMetadataKeys.OPEN_WORLD_HINT));
    }

    private static String stringMetadata(Map<String, Object> metadata, String key) {
        Object value = metadata.get(key);
        return value instanceof String s ? s : null;
    }

    private static Boolean booleanMetadata(Map<String, Object> metadata, String key) {
        Object value = metadata.get(key);
        return value instanceof Boolean b ? b : null;
    }

    private String serializeToolParameters(ToolSpecification spec) {
        if (spec.parameters() == null) {
            return "{}";
        }
        try {
            Map<String, Object> schemaMap = objectSchemaToMap(spec.parameters());
            return objectMapper.writeValueAsString(schemaMap);
        } catch (JsonProcessingException e) {
            logging.logToError("Failed to serialize tool parameters for '" + spec.name() + "': " + e.getMessage());
            eventLog.warn("Failed to serialize tool parameters for '" + spec.name() + "': " + e.getMessage());
            return "{}";
        }
    }

    private static McpResourceDefinition toResourceDefinition(McpResource resource) {
        return new McpResourceDefinition(
                resource.uri(), resource.name(), resource.description(), resource.mimeType());
    }

    private static McpResourceTemplateDefinition toResourceTemplateDefinition(McpResourceTemplate template) {
        return new McpResourceTemplateDefinition(
                template.uriTemplate(), template.name(), template.description(), template.mimeType());
    }

    private static McpPromptDefinition toPromptDefinition(McpPrompt prompt) {
        List<PromptArgument> arguments = prompt.arguments() == null
                ? List.of()
                : prompt.arguments().stream()
                        .map(McpDiscoveryClient::toPromptArgument)
                        .toList();
        return new McpPromptDefinition(prompt.name(), prompt.description(), arguments);
    }

    private static PromptArgument toPromptArgument(McpPromptArgument argument) {
        return new PromptArgument(argument.name(), argument.description(), argument.required());
    }

    private static Map<String, Object> objectSchemaToMap(JsonObjectSchema schema) {
        Map<String, Object> result = new LinkedHashMap<>();
        result.put("type", "object");

        if (schema.properties() != null && !schema.properties().isEmpty()) {
            Map<String, Object> properties = new LinkedHashMap<>();
            for (Map.Entry<String, JsonSchemaElement> entry : schema.properties().entrySet()) {
                properties.put(entry.getKey(), elementToMap(entry.getValue()));
            }
            result.put("properties", properties);
        }
        if (schema.required() != null && !schema.required().isEmpty()) {
            result.put("required", schema.required());
        }
        addDescription(result, schema.description());
        addAdditionalProperties(result, schema.additionalProperties());
        return result;
    }

    private static Map<String, Object> elementToMap(JsonSchemaElement element) {
        return SCHEMA_CONVERTERS.getOrDefault(element.getClass(), UNKNOWN_SCHEMA_HANDLER).apply(element);
    }

    private static Map<Class<? extends JsonSchemaElement>, Function<JsonSchemaElement, Map<String, Object>>> buildSchemaConverters() {
        Map<Class<? extends JsonSchemaElement>, Function<JsonSchemaElement, Map<String, Object>>> converters = new HashMap<>();
        converters.put(JsonObjectSchema.class, e -> objectSchemaToMap((JsonObjectSchema) e));
        converters.put(JsonArraySchema.class, e -> arraySchemaToMap((JsonArraySchema) e));
        converters.put(JsonEnumSchema.class, e -> enumSchemaToMap((JsonEnumSchema) e));
        converters.put(JsonAnyOfSchema.class, e -> anyOfSchemaToMap((JsonAnyOfSchema) e));
        converters.put(JsonReferenceSchema.class, e -> referenceSchemaToMap((JsonReferenceSchema) e));
        converters.put(JsonStringSchema.class, e -> primitiveSchema("string", ((JsonStringSchema) e).description()));
        converters.put(JsonIntegerSchema.class, e -> primitiveSchema("integer", ((JsonIntegerSchema) e).description()));
        converters.put(JsonNumberSchema.class, e -> primitiveSchema("number", ((JsonNumberSchema) e).description()));
        converters.put(JsonBooleanSchema.class, e -> primitiveSchema("boolean", ((JsonBooleanSchema) e).description()));
        return Map.copyOf(converters);
    }

    private static Map<String, Object> primitiveSchema(String type, String description) {
        Map<String, Object> result = new LinkedHashMap<>();
        result.put("type", type);
        addDescription(result, description);
        return result;
    }

    private static Map<String, Object> arraySchemaToMap(JsonArraySchema schema) {
        Map<String, Object> result = new LinkedHashMap<>();
        result.put("type", "array");
        if (schema.items() != null) {
            result.put("items", elementToMap(schema.items()));
        }
        addDescription(result, schema.description());
        return result;
    }

    private static Map<String, Object> enumSchemaToMap(JsonEnumSchema schema) {
        Map<String, Object> result = new LinkedHashMap<>();
        result.put("type", "string");
        if (schema.enumValues() != null) {
            result.put("enum", schema.enumValues());
        }
        addDescription(result, schema.description());
        return result;
    }

    private static Map<String, Object> anyOfSchemaToMap(JsonAnyOfSchema schema) {
        Map<String, Object> result = new LinkedHashMap<>();
        if (schema.anyOf() != null) {
            List<Map<String, Object>> options = schema.anyOf().stream()
                    .map(McpDiscoveryClient::elementToMap)
                    .toList();
            result.put("anyOf", options);
        }
        addDescription(result, schema.description());
        return result;
    }

    private static Map<String, Object> referenceSchemaToMap(JsonReferenceSchema schema) {
        Map<String, Object> result = new LinkedHashMap<>();
        result.put("$ref", schema.reference());
        return result;
    }

    private static void addDescription(Map<String, Object> map, String description) {
        if (description != null && !description.isEmpty()) {
            map.put("description", description);
        }
    }

    private static void addAdditionalProperties(Map<String, Object> map, Boolean additionalProperties) {
        if (additionalProperties != null) {
            map.put("additionalProperties", additionalProperties);
        }
    }
}
