package com.mcpscanner.scan;

import com.fasterxml.jackson.databind.JsonNode;
import com.mcpscanner.checks.shared.probe.McpMethodClass;
import com.mcpscanner.mcp.McpResourceDefinition;
import com.mcpscanner.mcp.McpToolDefinition;
import com.mcpscanner.scan.request.AdvertisedAuthorizationServer;
import com.mcpscanner.scan.request.GeneratedScan;
import com.mcpscanner.scan.request.McpMessage;
import com.mcpscanner.scan.request.RequestFamily;
import com.mcpscanner.scan.request.ServerCapabilities;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicReference;

import static org.assertj.core.api.Assertions.assertThat;

class ScanPlannerTest {

    private static final McpToolDefinition GET_DOCUMENT = new McpToolDefinition("get_document", "",
            "{\"type\":\"object\",\"properties\":{\"doc_id\":{\"type\":\"string\"},"
                    + "\"query\":{\"type\":\"string\",\"default\":\"all\"},\"page\":{\"type\":\"integer\"}},"
                    + "\"required\":[\"doc_id\",\"query\",\"page\"]}");
    private static final McpResourceDefinition RESOURCE =
            new McpResourceDefinition("file:///doc_id.txt", "doc", "", "text/plain", List.of());

    private final AtomicReference<Map<String, String>> ownedObjects = new AtomicReference<>(Map.of());
    private final ScanPlanner planner = new ScanPlanner(family -> true,
            () -> new ServerCapabilities(Map.of("tools", Map.of(), "resources", Map.of())), () -> "2025-06-18",
            AdvertisedAuthorizationServer::none, tool -> ownedObjects.get());

    @Test
    void scanAllCallsAToolWithTheOwnedValueInPlaceOfTheSchemaDefault() {
        ownedObjects.set(Map.of("doc_id", "d-alice-0001"));

        JsonNode arguments = toolArguments(planner.planSelection(ScanInventory.toolsOnly(List.of(GET_DOCUMENT))));

        assertThat(arguments.path("doc_id").asText()).isEqualTo("d-alice-0001");
    }

    @Test
    void scanThisRequestCallsAToolWithTheOwnedValueInPlaceOfTheSchemaDefault() {
        ownedObjects.set(Map.of("page", "7"));

        JsonNode arguments = toolArguments(planner.planItem(new ScanTarget.Tool(GET_DOCUMENT)));

        assertThat(arguments.path("page").isNumber()).isTrue();
        assertThat(arguments.path("page").asInt()).isEqualTo(7);
    }

    @Test
    void argumentsWithoutAnOwnedObjectKeepTheirSchemaDefaults() {
        JsonNode unowned = toolArguments(planner.planItem(new ScanTarget.Tool(GET_DOCUMENT)));
        ownedObjects.set(Map.of("doc_id", "d-alice-0001"));

        JsonNode owned = toolArguments(planner.planItem(new ScanTarget.Tool(GET_DOCUMENT)));

        assertThat(owned.path("query")).isEqualTo(unowned.path("query"));
        assertThat(owned.path("page")).isEqualTo(unowned.path("page"));
    }

    @Test
    void withNoOwnedObjectsTheGeneratedRequestsAreThoseOfTheSchemaDefaults() {
        ScanInventory inventory = new ScanInventory(List.of(GET_DOCUMENT), List.of(RESOURCE), List.of(), List.of());

        GeneratedScan scan = planner.planSelection(inventory);

        assertThat(toolArguments(scan).path("doc_id").asText()).isNotEqualTo("d-alice-0001");
        assertThat(scan.invokedTools()).containsExactly(GET_DOCUMENT);
    }

    @Test
    void resourceReadsAreUnaffectedByOwnedObjects() {
        ScanInventory inventory = new ScanInventory(List.of(), List.of(RESOURCE), List.of(), List.of());
        GeneratedScan unowned = planner.planSelection(inventory);
        ownedObjects.set(Map.of("doc_id", "d-alice-0001"));

        assertThat(planner.planSelection(inventory)).isEqualTo(unowned);
    }

    @Test
    void ownedObjectsAreReadAtPlanTime() {
        ownedObjects.set(Map.of("doc_id", "first"));
        planner.planItem(new ScanTarget.Tool(GET_DOCUMENT));
        ownedObjects.set(Map.of("doc_id", "second"));

        assertThat(toolArguments(planner.planItem(new ScanTarget.Tool(GET_DOCUMENT))).path("doc_id").asText())
                .isEqualTo("second");
    }

    @Test
    void withNothingTickedNoToolIsCalledEvenThoughTheServerAdvertisesTools() {
        GeneratedScan scan = planner.planSelection(ScanInventory.empty());

        assertThat(scan.messages()).isNotEmpty()
                .noneMatch(message -> message.family().group().invokesInventoryItems());
        assertThat(scan.invokedTools()).isEmpty();
    }

    @Test
    void withNothingTickedEveryProtocolRequestIsOutsideTheOperationClassThatAnonymousExecutionReports() {
        ScanPlanner everyCapability = new ScanPlanner(family -> true, () -> new ServerCapabilities(Map.of(
                "tools", Map.of(), "resources", Map.of("subscribe", true), "prompts", Map.of(),
                "logging", Map.of(), "completions", Map.of())), () -> "2026-07-28",
                AdvertisedAuthorizationServer::none, tool -> Map.of());

        List<String> methods = everyCapability.planSelection(ScanInventory.empty()).messages().stream()
                .filter(McpMessage.class::isInstance).map(McpMessage.class::cast)
                .filter(message -> !message.notification()).map(McpMessage::method).toList();

        assertThat(methods).isNotEmpty().allSatisfy(method ->
                assertThat(McpMethodClass.of(method, false)).isNotEqualTo(McpMethodClass.OPERATION));
    }

    private static JsonNode toolArguments(GeneratedScan scan) {
        return scan.messages().stream()
                .filter(message -> message.family() == RequestFamily.TOOLS_CALL)
                .map(McpMessage.class::cast)
                .findFirst().orElseThrow()
                .params().orElseThrow().path("arguments");
    }
}
