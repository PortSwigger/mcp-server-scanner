package com.mcpscanner.scan.request;

import com.mcpscanner.mcp.McpToolDefinition;
import com.mcpscanner.scan.ArgumentPath;
import com.mcpscanner.scan.ScanInventory;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.junit.jupiter.params.provider.EnumSource;

import java.util.EnumSet;
import com.mcpscanner.performance.RequestBudgets;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Random;
import java.util.Set;
import java.util.stream.IntStream;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class RequestGeneratorTest {

    private final RequestGenerator generator = RequestGenerator.standard();

    @Test
    void scanAllWithEverythingOnCoversEveryFamilyAndMethod() {
        GeneratedScan scan = generator.scanAll(SampleSurfaces.full(), family -> true);

        assertThat(families(scan)).containsExactlyInAnyOrder(RequestFamily.values());
        assertThat(SampleSurfaces.jsonRpc(scan)).extracting(McpMessage::method).containsExactly(
                "tools/list", "resources/list", "resources/templates/list", "prompts/list",
                "initialize", "notifications/initialized", "notifications/cancelled", "notifications/progress",
                "notifications/roots/list_changed", "completion/complete", "completion/complete",
                "logging/setLevel", "ping", "resources/subscribe", "resources/unsubscribe", "server/discover",
                "tools/call", "tools/call", "resources/read", "resources/read", "prompts/get");
        assertThat(scan.messages().get(scan.messages().size() - 6)).isInstanceOf(ClientRegistrationMessage.class);
    }

    @Test
    void scanAllQueuesOnlyInvocationsAfterTheFirstInventoryInvocation() {
        List<McpToolDefinition> manyTools = IntStream.range(0, 50)
                .mapToObj(index -> new McpToolDefinition("tool_" + index, "d", "{\"type\":\"object\"}"))
                .toList();
        ServerSurface largeServer = new ServerSurface(new ScanInventory(manyTools, List.of(), List.of(), List.of()),
                new ServerCapabilities(SampleSurfaces.ALL_CAPABILITIES));

        List<RequestFamilyGroup> groups = generator.scanAll(largeServer, family -> true).messages().stream()
                .map(message -> message.family().group())
                .toList();

        int firstInvocation = groups.indexOf(RequestFamilyGroup.INVOCATION);
        assertThat(groups.subList(0, firstInvocation)).contains(RequestFamilyGroup.LISTING);
        assertThat(groups.subList(firstInvocation, groups.size())).containsOnly(RequestFamilyGroup.INVOCATION);
    }

    @Test
    void clientRegistrationIsGeneratedOnlyWhenTheServerAdvertisesARegistrationEndpoint() {
        assertThat(families(generator.scanAll(SampleSurfaces.full(), family -> true)))
                .contains(RequestFamily.CLIENT_REGISTRATION);
        assertThat(families(generator.scanAll(SampleSurfaces.withoutRegistration(), family -> true)))
                .doesNotContain(RequestFamily.CLIENT_REGISTRATION)
                .containsAll(EnumSet.complementOf(EnumSet.of(RequestFamily.CLIENT_REGISTRATION)));
    }

    @ParameterizedTest
    @EnumSource(RequestFamily.class)
    void switchingOneFamilyOffRemovesOnlyThatFamily(RequestFamily off) {
        GeneratedScan scan = generator.scanAll(SampleSurfaces.full(), family -> family != off);

        assertThat(families(scan)).doesNotContain(off)
                .containsAll(EnumSet.complementOf(EnumSet.of(off)));
    }

    @ParameterizedTest
    @EnumSource(RequestFamily.class)
    void switchingOnlyOneFamilyOnSendsOnlyThatFamily(RequestFamily on) {
        GeneratedScan scan = generator.scanAll(SampleSurfaces.full(), family -> family == on);

        assertThat(families(scan)).containsExactly(on);
    }

    @Test
    void randomCombinationsOfFamilySwitchesYieldExactlyTheEnabledFamilies() {
        Random random = new Random(20261106L);
        for (int round = 0; round < 2_000; round++) {
            Set<RequestFamily> enabled = EnumSet.noneOf(RequestFamily.class);
            for (RequestFamily family : RequestFamily.values()) {
                if (random.nextBoolean()) {
                    enabled.add(family);
                }
            }
            assertThat(families(generator.scanAll(SampleSurfaces.full(), enabled::contains)))
                    .as("enabled %s", enabled).isEqualTo(enabled);
        }
    }

    @Test
    void allFamiliesOffSendsNothing() {
        assertThat(generator.scanAll(SampleSurfaces.full(), family -> false).messages()).isEmpty();
    }

    @Test
    void capabilityGatedFamiliesAreSkippedWhenNotAdvertised() {
        ServerSurface bare = new ServerSurface(ScanInventory.empty(), ServerCapabilities.none());

        assertThat(families(generator.scanAll(bare, family -> true))).containsExactlyInAnyOrder(
                RequestFamily.INITIALIZE, RequestFamily.NOTIFICATION_INITIALIZED,
                RequestFamily.NOTIFICATION_CANCELLED, RequestFamily.NOTIFICATION_PROGRESS,
                RequestFamily.NOTIFICATION_ROOTS_LIST_CHANGED, RequestFamily.PING, RequestFamily.SERVER_DISCOVER);
    }

    @Test
    void listRequestsFollowAdvertisedCapabilitiesWithoutInventory() {
        ServerSurface advertisedOnly = new ServerSurface(ScanInventory.empty(),
                new ServerCapabilities(Map.of("tools", Map.of(), "resources", Map.of(), "prompts", Map.of())));

        assertThat(families(generator.scanAll(advertisedOnly, family -> true))).contains(
                RequestFamily.TOOLS_LIST, RequestFamily.RESOURCES_LIST, RequestFamily.RESOURCE_TEMPLATES_LIST,
                RequestFamily.PROMPTS_LIST).doesNotContain(RequestFamily.SUBSCRIBE, RequestFamily.TOOLS_CALL);
    }

    @Test
    void discoveredInventoryProvesSupportWhenCapabilitiesWereNotCaptured() {
        ServerSurface noCapabilities = new ServerSurface(SampleSurfaces.fullInventory(), ServerCapabilities.none());

        assertThat(families(generator.scanAll(noCapabilities, family -> true))).contains(
                RequestFamily.TOOLS_CALL, RequestFamily.RESOURCES_READ, RequestFamily.RESOURCE_TEMPLATES_READ,
                RequestFamily.PROMPTS_GET, RequestFamily.TOOLS_LIST, RequestFamily.RESOURCES_LIST,
                RequestFamily.RESOURCE_TEMPLATES_LIST, RequestFamily.PROMPTS_LIST)
                .doesNotContain(RequestFamily.COMPLETION, RequestFamily.LOGGING, RequestFamily.SUBSCRIBE);
    }

    @Test
    void theStatelessLifecycleDropsTheHandshakeAndLoggingLevelRequests() {
        ServerSurface modern = new ServerSurface(SampleSurfaces.fullInventory(),
                SampleSurfaces.full().capabilities(), "2026-07-28");

        assertThat(families(generator.scanAll(modern, family -> true)))
                .doesNotContain(RequestFamily.INITIALIZE, RequestFamily.NOTIFICATION_INITIALIZED, RequestFamily.LOGGING)
                .contains(RequestFamily.SERVER_DISCOVER, RequestFamily.TOOLS_CALL,
                        RequestFamily.COMPLETION, RequestFamily.SUBSCRIBE);
    }

    @ParameterizedTest
    @ValueSource(strings = {"2024-11-05", "2025-03-26", "2025-06-18", "2025-11-25"})
    void handshakeVersionsKeepEveryFamily(String version) {
        ServerSurface handshake = new ServerSurface(SampleSurfaces.fullInventory(),
                SampleSurfaces.full().capabilities(), version, SampleSurfaces.full().authorizationServer());

        assertThat(families(generator.scanAll(handshake, family -> true)))
                .isEqualTo(families(generator.scanAll(SampleSurfaces.full(), family -> true)));
    }

    @Test
    void subscribeNeedsTheSubscribeCapabilityFlag() {
        ServerSurface noSubscribe = new ServerSurface(SampleSurfaces.fullInventory(),
                new ServerCapabilities(Map.of("resources", Map.of("subscribe", false))));

        assertThat(families(generator.scanAll(noSubscribe, family -> true))).doesNotContain(RequestFamily.SUBSCRIBE);
    }

    @Test
    void invokedToolsListEveryToolCalledByScanAll() {
        assertThat(generator.scanAll(SampleSurfaces.full(), family -> true).invokedTools())
                .containsExactly(SampleSurfaces.READ_TOOL, SampleSurfaces.WRITE_TOOL);
        assertThat(generator.scanAll(SampleSurfaces.full(), family -> family != RequestFamily.TOOLS_CALL)
                .invokedTools()).isEmpty();
    }

    @Test
    void scanThisRequestBuildsExactlyTheChosenToolCallIgnoringCapabilities() {
        GeneratedScan scan = generator.scanThisRequest(RequestFamily.TOOLS_CALL,
                ScanInventory.toolsOnly(List.of(SampleSurfaces.WRITE_TOOL)));

        assertThat(SampleSurfaces.jsonRpc(scan)).singleElement().satisfies(message -> {
            assertThat(message.method()).isEqualTo("tools/call");
            assertThat(message.routingName()).contains("delete_file");
        });
        assertThat(scan.invokedTools()).containsExactly(SampleSurfaces.WRITE_TOOL);
    }

    @Test
    void anOptionalFieldLeftOutOfTheBaseCallGetsItsOwnProbeCallSoChecksCanFuzzIt() {
        McpToolDefinition tool = new McpToolDefinition("list_rows", "d",
                "{\"type\":\"object\",\"properties\":{\"table\":{\"type\":\"string\"},"
                        + "\"sort\":{\"type\":\"string\",\"pattern\":\"^[a-z_]+$\"}},\"required\":[\"table\"]}");

        List<McpMessage> calls = SampleSurfaces.jsonRpc(generator.scanThisRequest(RequestFamily.TOOLS_CALL,
                ScanInventory.toolsOnly(List.of(tool))));

        assertThat(calls).extracting(call -> call.params().orElseThrow().path("arguments").has("sort"))
                .containsExactly(false, true);
        assertThat(calls).allSatisfy(call -> assertThat(call.params().orElseThrow().path("arguments")
                .has("table")).isTrue());
    }

    @Test
    void oneToolWithTwoPatternBoundOptionalArgumentsIsScannedAsTheBaseCallPlusOneProbeEach() {
        McpToolDefinition tool = new McpToolDefinition("list_rows", "d",
                "{\"type\":\"object\",\"properties\":{\"table\":{\"type\":\"string\"},"
                        + "\"sort\":{\"type\":\"string\",\"pattern\":\"^[a-z_]+$\"},"
                        + "\"rows\":{\"type\":\"array\",\"items\":{\"type\":\"object\",\"properties\":"
                        + "{\"ref\":{\"type\":\"string\",\"pattern\":\"^[a-z]+$\"}}}}},\"required\":[\"table\"]}");

        List<McpMessage> calls = SampleSurfaces.jsonRpc(generator.scanThisRequest(RequestFamily.TOOLS_CALL,
                ScanInventory.toolsOnly(List.of(tool))));

        RequestBudgets.assertWithin("Generated calls for one tool with two pattern-bound optional arguments",
                calls.stream().map(McpMessage::subject).toList());
    }

    @Test
    void aProbeCallNamesTheOneArgumentItAddedAndTheBaseCallNamesNone() {
        McpToolDefinition tool = new McpToolDefinition("list_rows", "d",
                "{\"type\":\"object\",\"properties\":{\"table\":{\"type\":\"string\"},"
                        + "\"opts\":{\"type\":\"object\",\"properties\":{\"sort\":{\"type\":\"string\","
                        + "\"pattern\":\"^[a-z_]+$\"}}}},\"required\":[\"table\"]}");

        List<McpMessage> calls = SampleSurfaces.jsonRpc(generator.scanThisRequest(RequestFamily.TOOLS_CALL,
                ScanInventory.toolsOnly(List.of(tool))));

        assertThat(calls).extracting(McpMessage::addedArgument)
                .containsExactly(Optional.empty(), Optional.of(ArgumentPath.of("opts", "sort")));
        assertThat(calls.get(1).params().orElseThrow().at("/arguments/opts/sort").asText()).isEqualTo("test");
    }

    @Test
    void scanThisRequestBuildsTheChosenResourceTemplateAndPrompt() {
        assertThat(generator.scanThisRequest(RequestFamily.RESOURCES_READ,
                new ScanInventory(List.of(), List.of(SampleSurfaces.RESOURCE), List.of(), List.of())).messages())
                .extracting(ScanMessage::subject).containsExactly("resources/read file:///notes.txt");
        assertThat(generator.scanThisRequest(RequestFamily.RESOURCE_TEMPLATES_READ,
                new ScanInventory(List.of(), List.of(), List.of(SampleSurfaces.TEMPLATE), List.of())).messages())
                .extracting(ScanMessage::subject).containsExactly("resources/read file:///docs/name");
        GeneratedScan prompt = generator.scanThisRequest(RequestFamily.PROMPTS_GET,
                new ScanInventory(List.of(), List.of(), List.of(), List.of(SampleSurfaces.PROMPT)));
        assertThat(prompt.messages()).extracting(ScanMessage::subject).containsExactly("prompts/get greet");
        assertThat(prompt.invokedTools()).isEmpty();
    }

    @Test
    void duplicateFamilyBuildersAreRejected() {
        assertThatThrownBy(() -> new RequestGenerator(List.of(new ToolCallRequests(), new ToolCallRequests())))
                .isInstanceOf(IllegalArgumentException.class).hasMessageContaining("TOOLS_CALL");
    }

    @Test
    void standardCatalogHasOneBuilderPerFamily() {
        assertThat(RequestFamilyCatalog.standard()).extracting(RequestFamilyBuilder::family)
                .containsExactly(RequestFamily.values());
    }

    private static Set<RequestFamily> families(GeneratedScan scan) {
        Set<RequestFamily> families = EnumSet.noneOf(RequestFamily.class);
        scan.messages().forEach(message -> families.add(message.family()));
        return families;
    }
}
