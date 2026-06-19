package com.mcpscanner.client;

import burp.api.montoya.logging.Logging;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.core.type.TypeReference;
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
import com.mcpscanner.testutil.MontoyaTestFactory;
import dev.langchain4j.agent.tool.ToolSpecification;
import dev.langchain4j.mcp.client.McpClient;
import dev.langchain4j.mcp.client.McpPrompt;
import dev.langchain4j.mcp.client.McpPromptArgument;
import dev.langchain4j.mcp.client.McpResource;
import dev.langchain4j.mcp.client.McpResourceTemplate;
import dev.langchain4j.mcp.client.McpToolMetadataKeys;
import dev.langchain4j.model.chat.request.json.JsonObjectSchema;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.atLeastOnce;
import static org.mockito.Mockito.contains;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class McpDiscoveryClientTest {

    @Mock private Logging logging;
    @Mock private McpClient mcpClient;

    @BeforeAll
    static void installMontoyaFactory() {
        MontoyaTestFactory.install();
    }

    @Test
    void discoverToolsReturnsEmptyWhenNoToolsAdvertised() {
        when(mcpClient.listTools()).thenReturn(List.of());
        McpDiscoveryClient discovery = new McpDiscoveryClient(mcpClient, logging);

        assertThat(discovery.discoverTools()).isEmpty();
    }

    @Test
    void discoverToolsReturnsToolWithEmptySchemaWhenParametersAreNull() {
        ToolSpecification spec = ToolSpecification.builder()
                .name("noop")
                .description("does nothing")
                .build();
        when(mcpClient.listTools()).thenReturn(List.of(spec));
        McpDiscoveryClient discovery = new McpDiscoveryClient(mcpClient, logging);

        List<McpToolDefinition> tools = discovery.discoverTools();

        assertThat(tools).hasSize(1);
        assertThat(tools.get(0).name()).isEqualTo("noop");
        assertThat(tools.get(0).inputSchema()).isEqualTo("{}");
    }

    @Test
    void discoverToolsSerialisesParametersAsJsonSchema() throws Exception {
        JsonObjectSchema parameters = JsonObjectSchema.builder()
                .addStringProperty("message", "The message to send")
                .required("message")
                .build();
        ToolSpecification spec = ToolSpecification.builder()
                .name("send")
                .description("Sends a message")
                .parameters(parameters)
                .build();
        when(mcpClient.listTools()).thenReturn(List.of(spec));
        McpDiscoveryClient discovery = new McpDiscoveryClient(mcpClient, logging);

        List<McpToolDefinition> tools = discovery.discoverTools();

        ObjectMapper mapper = new ObjectMapper();
        Map<String, Object> schema = mapper.readValue(tools.get(0).inputSchema(), new TypeReference<>() {});
        assertThat(schema.get("type")).isEqualTo("object");
        @SuppressWarnings("unchecked")
        Map<String, Object> properties = (Map<String, Object>) schema.get("properties");
        assertThat(properties).containsKey("message");
        @SuppressWarnings("unchecked")
        List<String> required = (List<String>) schema.get("required");
        assertThat(required).containsExactly("message");
    }

    @Test
    void populatesAnnotationsFromLangchain4jMetadata() {
        ToolSpecification spec = ToolSpecification.builder()
                .name("writer")
                .description("writes things")
                .addMetadata(McpToolMetadataKeys.READ_ONLY_HINT, Boolean.TRUE)
                .addMetadata(McpToolMetadataKeys.DESTRUCTIVE_HINT, Boolean.FALSE)
                .addMetadata(McpToolMetadataKeys.IDEMPOTENT_HINT, Boolean.TRUE)
                .addMetadata(McpToolMetadataKeys.OPEN_WORLD_HINT, Boolean.FALSE)
                .addMetadata(McpToolMetadataKeys.TITLE_ANNOTATION, "Writer Tool")
                .build();
        when(mcpClient.listTools()).thenReturn(List.of(spec));
        McpDiscoveryClient discovery = new McpDiscoveryClient(mcpClient, logging);

        List<McpToolDefinition> tools = discovery.discoverTools();

        assertThat(tools).hasSize(1);
        ToolAnnotations annotations = tools.get(0).annotations();
        assertThat(annotations.readOnlyHint()).isTrue();
        assertThat(annotations.destructiveHint()).isFalse();
        assertThat(annotations.idempotentHint()).isTrue();
        assertThat(annotations.openWorldHint()).isFalse();
        assertThat(annotations.title()).isEqualTo("Writer Tool");
    }

    @Test
    void discoverToolsLogsAndReturnsEmptySchemaWhenSerialisationFails() throws Exception {
        ObjectMapper failingMapper = mock(ObjectMapper.class);
        lenient().when(failingMapper.writeValueAsString(any()))
                .thenThrow(new JsonProcessingException("boom") {});
        JsonObjectSchema parameters = JsonObjectSchema.builder()
                .addStringProperty("message")
                .build();
        ToolSpecification spec = ToolSpecification.builder()
                .name("send")
                .description("Sends a message")
                .parameters(parameters)
                .build();
        when(mcpClient.listTools()).thenReturn(List.of(spec));
        McpDiscoveryClient discovery = new McpDiscoveryClient(mcpClient, logging, failingMapper);

        List<McpToolDefinition> tools = discovery.discoverTools();

        assertThat(tools).hasSize(1);
        assertThat(tools.get(0).inputSchema()).isEqualTo("{}");
        verify(logging, atLeastOnce()).logToError(contains("Failed to serialize tool parameters"));
    }

    @Test
    void discoverResourcesMapsLangchainResources() {
        McpResource readme = new McpResource(
                "docs://readme", "Readme", "Server overview", "text/plain");
        when(mcpClient.listResources()).thenReturn(List.of(readme));
        McpDiscoveryClient discovery = new McpDiscoveryClient(mcpClient, logging);

        List<McpResourceDefinition> resources = discovery.discoverResources();

        assertThat(resources).containsExactly(new McpResourceDefinition(
                "docs://readme", "Readme", "Server overview", "text/plain"));
    }

    @Test
    void discoverResourcesReturnsEmptyAndLogsWhenClientThrows() {
        when(mcpClient.listResources()).thenThrow(new RuntimeException("method not found"));
        McpDiscoveryClient discovery = new McpDiscoveryClient(mcpClient, logging);

        assertThat(discovery.discoverResources()).isEmpty();
        verify(logging, atLeastOnce()).logToOutput(contains("does not advertise resources"));
    }

    @Test
    void discoverResourceTemplatesMapsLangchainTemplates() {
        McpResourceTemplate template = new McpResourceTemplate(
                "file:///{path}", "files", "files under root", "text/plain");
        when(mcpClient.listResourceTemplates()).thenReturn(List.of(template));
        McpDiscoveryClient discovery = new McpDiscoveryClient(mcpClient, logging);

        List<McpResourceTemplateDefinition> templates = discovery.discoverResourceTemplates();

        assertThat(templates).containsExactly(new McpResourceTemplateDefinition(
                "file:///{path}", "files", "files under root", "text/plain"));
    }

    @Test
    void discoverResourceTemplatesReturnsEmptyAndLogsWhenClientThrows() {
        when(mcpClient.listResourceTemplates()).thenThrow(new RuntimeException("not supported"));
        McpDiscoveryClient discovery = new McpDiscoveryClient(mcpClient, logging);

        assertThat(discovery.discoverResourceTemplates()).isEmpty();
        verify(logging, atLeastOnce()).logToOutput(contains("does not advertise resource templates"));
    }

    @Test
    void discoverPromptsMapsLangchainPrompts() {
        McpPromptArgument arg = new McpPromptArgument("text", "the body", true);
        McpPrompt summarize = new McpPrompt("summarize", "summarise text", List.of(arg));
        when(mcpClient.listPrompts()).thenReturn(List.of(summarize));
        McpDiscoveryClient discovery = new McpDiscoveryClient(mcpClient, logging);

        List<McpPromptDefinition> prompts = discovery.discoverPrompts();

        assertThat(prompts).hasSize(1);
        assertThat(prompts.get(0).name()).isEqualTo("summarize");
        assertThat(prompts.get(0).arguments())
                .containsExactly(new PromptArgument("text", "the body", true));
    }

    @Test
    void discoverPromptsReturnsEmptyAndLogsWhenClientThrows() {
        when(mcpClient.listPrompts()).thenThrow(new RuntimeException("prompts not supported"));
        McpDiscoveryClient discovery = new McpDiscoveryClient(mcpClient, logging);

        assertThat(discovery.discoverPrompts()).isEmpty();
        verify(logging, atLeastOnce()).logToOutput(contains("does not advertise prompts"));
    }

    @Test
    void fetchServerMetadataReturnsEmptyWhenInitializeResultIsNull() {
        McpDiscoveryClient discovery = new McpDiscoveryClient(mcpClient, logging);

        ServerMetadata metadata = discovery.fetchServerMetadata(null);

        assertThat(metadata).isEqualTo(ServerMetadata.empty());
    }

    @Test
    void populatesServerMetadataFromLangchain4jInitializeResult() throws Exception {
        // langchain4j-mcp transports return the full JSON-RPC envelope JsonNode from
        // McpTransport.initialize(...): {"jsonrpc":"2.0","id":N,"result":{serverInfo,instructions,capabilities,...}}.
        // This shape is identical on SSE and Streamable HTTP because the langchain4j transport
        // already handles each protocol's wire dance internally.
        String envelopeJson = "{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{"
                + "\"protocolVersion\":\"2024-11-05\","
                + "\"capabilities\":{\"tools\":{\"listChanged\":true},\"resources\":{}},"
                + "\"instructions\":\"hello from langchain4j\","
                + "\"serverInfo\":{\"name\":\"lc4j-server\",\"version\":\"4.2\"}}}";
        com.fasterxml.jackson.databind.JsonNode initializeEnvelope =
                com.mcpscanner.mcp.McpObjectMapper.INSTANCE.readTree(envelopeJson);

        McpDiscoveryClient discovery = new McpDiscoveryClient(mcpClient, logging);

        ServerMetadata metadata = discovery.fetchServerMetadata(initializeEnvelope);

        assertThat(metadata.serverInfo())
                .containsEntry("name", "lc4j-server")
                .containsEntry("version", "4.2");
        assertThat(metadata.instructions()).isEqualTo("hello from langchain4j");
        assertThat(metadata.capabilities()).containsKeys("tools", "resources");
    }

    @Test
    void discoverResourcesUnsupportedLogsInfoToEventLog() {
        when(mcpClient.listResources()).thenThrow(new RuntimeException("method not found"));
        McpEventLog eventLog = new McpEventLog(null);
        McpDiscoveryClient discovery = new McpDiscoveryClient(mcpClient, logging, eventLog);

        discovery.discoverResources();

        assertThat(eventLog.snapshot())
                .anyMatch(entry -> entry.level() == McpEventLog.Level.INFO
                        && entry.message().equals("Server does not advertise resources"));
    }

    @Test
    void discoverResourceTemplatesUnsupportedLogsInfoToEventLog() {
        when(mcpClient.listResourceTemplates()).thenThrow(new RuntimeException("not supported"));
        McpEventLog eventLog = new McpEventLog(null);
        McpDiscoveryClient discovery = new McpDiscoveryClient(mcpClient, logging, eventLog);

        discovery.discoverResourceTemplates();

        assertThat(eventLog.snapshot())
                .anyMatch(entry -> entry.level() == McpEventLog.Level.INFO
                        && entry.message().equals("Server does not advertise resource templates"));
    }

    @Test
    void discoverPromptsUnsupportedLogsInfoToEventLog() {
        when(mcpClient.listPrompts()).thenThrow(new RuntimeException("not supported"));
        McpEventLog eventLog = new McpEventLog(null);
        McpDiscoveryClient discovery = new McpDiscoveryClient(mcpClient, logging, eventLog);

        discovery.discoverPrompts();

        assertThat(eventLog.snapshot())
                .anyMatch(entry -> entry.level() == McpEventLog.Level.INFO
                        && entry.message().equals("Server does not advertise prompts"));
    }

    @Test
    void closeDelegatesToUnderlyingClient() throws Exception {
        McpDiscoveryClient discovery = new McpDiscoveryClient(mcpClient, logging);

        discovery.close();

        verify(mcpClient).close();
    }

    @Test
    void populatesToolIconsFromCapturedEnvelope() throws Exception {
        // The CapturingMcpTransport decorator stores the JSON-RPC envelope returned by
        // langchain4j's tools/list call. McpDiscoveryClient parses icons out of that
        // envelope and merges them onto the corresponding tool definitions — this is
        // transport-agnostic because the envelope is identical on Streamable HTTP and SSE.
        ToolSpecification spec = ToolSpecification.builder()
                .name("hello")
                .description("greets the world")
                .build();
        when(mcpClient.listTools()).thenReturn(List.of(spec));
        JsonNode envelope = McpObjectMapper.INSTANCE.readTree(
                "{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{\"tools\":["
                        + "{\"name\":\"hello\",\"icons\":["
                        + "{\"src\":\"data:image/png;base64,iVBORw0K\",\"mimeType\":\"image/png\","
                        + "\"sizes\":[\"32x32\"]}]}]}}");
        McpDiscoveryClient discovery = new McpDiscoveryClient(mcpClient, logging);

        List<McpToolDefinition> tools = discovery.discoverToolsWithIcons(() -> envelope);

        assertThat(tools).hasSize(1);
        List<IconDescriptor> icons = tools.get(0).icons();
        assertThat(icons).hasSize(1);
        assertThat(icons.get(0).src()).isEqualTo("data:image/png;base64,iVBORw0K");
        assertThat(icons.get(0).mimeType()).isEqualTo("image/png");
        assertThat(icons.get(0).sizes()).containsExactly("32x32");
    }

    @Test
    void discoverToolsWithIconsReadsEnvelopeAfterListToolsDrivesTheTransport() {
        // The supplier must be read after discoverTools() has been invoked, since
        // CapturingMcpTransport only populates the envelope once the underlying
        // listTools() call has driven the transport.
        ToolSpecification spec = ToolSpecification.builder().name("hello").build();
        when(mcpClient.listTools()).thenReturn(List.of(spec));
        McpDiscoveryClient discovery = new McpDiscoveryClient(mcpClient, logging);
        java.util.concurrent.atomic.AtomicInteger order = new java.util.concurrent.atomic.AtomicInteger();
        when(mcpClient.listTools()).thenAnswer(invocation -> {
            order.set(1);
            return List.of(spec);
        });

        discovery.discoverToolsWithIcons(() -> {
            assertThat(order.get())
                    .as("envelope supplier must be invoked after listTools()")
                    .isEqualTo(1);
            return null;
        });
    }

    @Test
    void discoverToolsWithIconsReturnsPlainToolsWhenEnvelopeIsNull() {
        ToolSpecification spec = ToolSpecification.builder().name("plain").build();
        when(mcpClient.listTools()).thenReturn(List.of(spec));
        McpDiscoveryClient discovery = new McpDiscoveryClient(mcpClient, logging);

        List<McpToolDefinition> tools = discovery.discoverToolsWithIcons(() -> null);

        assertThat(tools).hasSize(1);
        assertThat(tools.get(0).icons()).isEmpty();
    }

    @Test
    void populatesResourceIconsFromCapturedEnvelope() throws Exception {
        McpResource readme = new McpResource(
                "docs://readme", "Readme", "Server overview", "text/plain");
        when(mcpClient.listResources()).thenReturn(List.of(readme));
        JsonNode envelope = McpObjectMapper.INSTANCE.readTree(
                "{\"jsonrpc\":\"2.0\",\"id\":2,\"result\":{\"resources\":["
                        + "{\"name\":\"Readme\",\"icons\":["
                        + "{\"src\":\"https://cdn.example/readme.png\",\"mimeType\":\"image/png\"}]}]}}");
        McpDiscoveryClient discovery = new McpDiscoveryClient(mcpClient, logging);

        List<McpResourceDefinition> resources = discovery.discoverResourcesWithIcons(() -> envelope);

        assertThat(resources).hasSize(1);
        assertThat(resources.get(0).icons()).hasSize(1);
        assertThat(resources.get(0).icons().get(0).src())
                .isEqualTo("https://cdn.example/readme.png");
    }

    @Test
    void populatesPromptIconsFromCapturedEnvelope() throws Exception {
        McpPromptArgument arg = new McpPromptArgument("text", "the body", true);
        McpPrompt summarize = new McpPrompt("summarise", "summarise text", List.of(arg));
        when(mcpClient.listPrompts()).thenReturn(List.of(summarize));
        JsonNode envelope = McpObjectMapper.INSTANCE.readTree(
                "{\"jsonrpc\":\"2.0\",\"id\":3,\"result\":{\"prompts\":["
                        + "{\"name\":\"summarise\",\"icons\":["
                        + "{\"src\":\"https://cdn.example/p.svg\",\"mimeType\":\"image/svg+xml\"}]}]}}");
        McpDiscoveryClient discovery = new McpDiscoveryClient(mcpClient, logging);

        List<McpPromptDefinition> prompts = discovery.discoverPromptsWithIcons(() -> envelope);

        assertThat(prompts).hasSize(1);
        assertThat(prompts.get(0).icons()).hasSize(1);
        assertThat(prompts.get(0).icons().get(0).mimeType()).isEqualTo("image/svg+xml");
    }

}
