package com.mcpscanner.access.mining;

import com.mcpscanner.identity.MinedSource;
import com.mcpscanner.identity.MinedValue;
import com.mcpscanner.identity.ValueScope;

import com.mcpscanner.checks.api.Principal;
import com.mcpscanner.mcp.McpResourceDefinition;
import com.mcpscanner.mcp.McpResourceTemplateDefinition;
import com.mcpscanner.mcp.McpToolDefinition;
import com.mcpscanner.scan.ScanInventory;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;

import java.util.ArrayList;
import java.util.List;
import com.mcpscanner.checks.api.PrincipalRole;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.stream.IntStream;

import static com.mcpscanner.access.mining.ScriptedServer.identity;
import static com.mcpscanner.access.mining.ScriptedServer.json;
import static com.mcpscanner.access.mining.ScriptedServer.noArguments;
import static com.mcpscanner.access.mining.ScriptedServer.readOnlyTool;
import static com.mcpscanner.access.mining.ScriptedServer.stringArgument;
import static com.mcpscanner.access.mining.ScriptedServer.structured;
import static com.mcpscanner.access.mining.ScriptedServer.unannotatedTool;
import static org.assertj.core.api.Assertions.assertThat;

class AccessMinerTest {

    private static final String ALICE_CAMPAIGN = "c0a11ce0-0000-4000-8000-000000055544";
    private static final String BOB_CAMPAIGN = "c0b0b000-0000-4000-8000-000000055544";
    private static final String ORG = "0rg00000-0000-4000-8000-000000000001";
    private static final Principal ALICE = identity("alice");
    private static final Principal BOB = identity("bob");

    private static final McpToolDefinition LIST_CAMPAIGNS = readOnlyTool("campaigns_list", noArguments());
    private static final McpToolDefinition GET_CAMPAIGN = readOnlyTool("campaigns_get", stringArgument("id"));

    private static final McpToolDefinition QUERY_RECORDS = readOnlyTool("query_records", noArguments());
    private static final McpToolDefinition READ_ATTACHMENT = readOnlyTool("read_attachment",
            "{\"type\":\"object\",\"properties\":{\"files\":{\"type\":\"array\",\"items\":{\"type\":\"object\","
                    + "\"properties\":{\"path\":{\"type\":[\"string\",\"null\"]},\"title\":{\"type\":[\"string\",\"null\"]},"
                    + "\"mimeType\":{\"type\":[\"string\",\"null\"]},\"size\":{\"type\":[\"number\",\"null\"]},"
                    + "\"signedPath\":{\"type\":[\"string\",\"null\"]}}}}},\"required\":[\"files\"]}");

    private static final int PASSES = MiningSettings.DEFAULT_PASSES;
    private static final int VALUES = MiningSettings.DEFAULT_VALUES_PER_ARGUMENT;
    private static final int REQUESTS = MiningSettings.NO_REQUEST_CEILING;
    private static final int PAGES = MiningSettings.DEFAULT_LIST_PAGES;

    private final ScriptedServer server = new ScriptedServer();
    private final ExecutorService workers = Executors.newFixedThreadPool(WORKERS);

    private static final int WORKERS = 4;

    @AfterEach
    void stopWorkers() {
        workers.shutdownNow();
    }

    @Test
    void sendsUpToTheWorkerCountOfCallsAtOnce() {
        InFlight inFlight = new InFlight(WORKERS);
        server.on(inFlight::held);

        new AccessMiner(server, MiningSettings.defaults().withPasses(1), workers)
                .mine(tools(listTools(8)), List.of(ALICE), MiningControl.unattended());

        assertThat(inFlight.most()).isEqualTo(WORKERS);
    }

    @Test
    void collectsForEveryUserAtOnce() {
        InFlight inFlight = new InFlight(2);
        server.on(inFlight::held);

        new AccessMiner(server, MiningSettings.defaults().withPasses(1), workers)
                .mine(tools(LIST_CAMPAIGNS), List.of(ALICE, BOB), MiningControl.unattended());

        assertThat(inFlight.identities()).contains("alice", "bob");
    }

    @Test
    void concurrentCollectingFindsExactlyWhatSequentialCollectingFinds() {
        scriptCampaignsAndOwners();
        ScanInventory catalog = tools(LIST_CAMPAIGNS, GET_CAMPAIGN, readOnlyTool("owners_get", stringArgument("owner_id")));

        MiningResult sequential = new AccessMiner(server, MiningSettings.defaults().withPasses(3))
                .mine(catalog, List.of(ALICE, BOB), MiningControl.unattended());
        MiningResult concurrent = new AccessMiner(server, MiningSettings.defaults().withPasses(3), workers)
                .mine(catalog, List.of(ALICE, BOB), MiningControl.unattended());

        assertThat(concurrent).isEqualTo(sequential);
        assertThat(concurrent.of("alice").orElseThrow().values()).extracting(MinedValue::value)
                .contains("owner-alice-2");
    }

    @Test
    void cancellingLeavesQueuedCallsUnsent() throws Exception {
        CountDownLatch started = new CountDownLatch(WORKERS);
        CountDownLatch release = new CountDownLatch(1);
        AtomicBoolean cancelled = new AtomicBoolean();
        server.on((identity, call) -> {
            started.countDown();
            awaitQuietly(release);
            return Optional.empty();
        });

        java.util.concurrent.CompletableFuture<MiningResult> run = java.util.concurrent.CompletableFuture.supplyAsync(
                () -> new AccessMiner(server, MiningSettings.defaults().withPasses(1), workers)
                        .mine(tools(listTools(20)), List.of(ALICE), new MiningControl(MiningProgress.NONE, cancelled::get)));
        assertThat(started.await(5, TimeUnit.SECONDS)).isTrue();
        cancelled.set(true);
        release.countDown();

        assertThat(run.get(5, TimeUnit.SECONDS).stop()).isEqualTo(MiningStop.CANCELLED);
        assertThat(server.sent()).hasSizeLessThanOrEqualTo(WORKERS * 2);
    }

    @Test
    void collectsEveryToolForEveryPassWithoutARequestLimitByDefault() {
        server.on((identity, call) -> call.params().path("name").asText().endsWith("_list")
                ? Optional.of(MiningReply.of(200, structured("{\"id\":\"" + uuidFor(call) + "\"}")))
                : Optional.empty());
        List<McpToolDefinition> many = new ArrayList<>(List.of(listTools(150)));
        IntStream.range(0, 150).forEach(index -> many.add(readOnlyTool("t" + index + "_get", stringArgument("id"))));

        MiningResult result = new AccessMiner(server, MiningSettings.defaults(), workers)
                .mine(ScanInventory.toolsOnly(many), List.of(ALICE), MiningControl.unattended());

        assertThat(result.of("alice").orElseThrow().warnings()).extracting(MiningWarning::kind)
                .doesNotContain(MiningWarning.Kind.REQUEST_LIMIT);
        assertThat(server.toolCalls("t149_get")).extracting(sent -> sent.arguments().path("id").asText())
                .contains("c0a11ce0-0000-4000-8000-000000000000");
    }

    @Test
    void aUserRequestCeilingNamesTheSettingThatRaisesIt() {
        MiningResult result = mine(MiningSettings.defaults().withRequestCeiling(4), tools(listTools(3)), ALICE);

        assertThat(result.of("alice").orElseThrow().warnings())
                .filteredOn(warning -> warning.kind() == MiningWarning.Kind.REQUEST_LIMIT)
                .extracting(MiningWarning::detail).singleElement().asString()
                .contains("Collect IDs requests per user", "4 requests");
    }

    @Test
    void theRequestCeilingHoldsWhenCallsRunConcurrently() {
        MiningResult result = new AccessMiner(server, limits(PASSES, VALUES, 9, PAGES), workers)
                .mine(tools(listTools(10)), List.of(ALICE), MiningControl.unattended());

        assertThat(aliceSent()).hasSizeLessThanOrEqualTo(9);
        assertThat(result.of("alice").orElseThrow().requestsSent()).isEqualTo(aliceSent().size());
    }

    private void scriptCampaignsAndOwners() {
        server.on((identity, call) -> {
            String tool = call.params().path("name").asText();
            String id = call.params().path("arguments").path("id").asText();
            if (tool.equals("campaigns_list")) {
                return Optional.of(MiningReply.of(200, structured("{\"campaigns\":[{\"id\":\"camp-" + identity.id()
                        + "-1\"},{\"id\":\"camp-" + identity.id() + "-2\"}]}")));
            }
            if (tool.equals("campaigns_get") && !id.isEmpty()) {
                return Optional.of(MiningReply.of(200, structured("{\"owner_id\":\"owner-" + identity.id() + "-"
                        + id.substring(id.length() - 1) + "\"}")));
            }
            return Optional.empty();
        });
    }

    private static String uuidFor(MiningCall call) {
        String tool = call.params().path("name").asText();
        return String.format("c0a11ce0-0000-4000-8000-%012d", Integer.parseInt(tool.substring(1, tool.indexOf('_'))));
    }

    private static McpToolDefinition[] listTools(int count) {
        return IntStream.range(0, count).mapToObj(index -> readOnlyTool("t" + index + "_list", noArguments()))
                .toArray(McpToolDefinition[]::new);
    }

    private static void awaitQuietly(CountDownLatch latch) {
        try {
            latch.await(5, TimeUnit.SECONDS);
        } catch (InterruptedException interrupted) {
            Thread.currentThread().interrupt();
        }
    }

    private static final class InFlight {
        private final CountDownLatch together;
        private final AtomicInteger current = new AtomicInteger();
        private final AtomicInteger most = new AtomicInteger();
        private final java.util.Set<String> identities = java.util.concurrent.ConcurrentHashMap.newKeySet();

        InFlight(int expected) {
            this.together = new CountDownLatch(expected);
        }

        Optional<MiningReply> held(Principal identity, MiningCall call) {
            most.accumulateAndGet(current.incrementAndGet(), Math::max);
            identities.add(identity.id());
            together.countDown();
            awaitQuietly(together);
            current.decrementAndGet();
            return Optional.empty();
        }

        int most() {
            return most.get();
        }

        java.util.Set<String> identities() {
            return identities;
        }
    }

    @Test
    void firstPassCallsEveryReadOnlyToolWithItsSchemaDefaults() {
        McpToolDefinition withDefault = readOnlyTool("campaigns_get",
                "{\"type\":\"object\",\"properties\":{\"id\":{\"type\":\"string\",\"default\":\"seed\"}}}");

        mine(MiningSettings.defaults().withPasses(1), tools(withDefault), ALICE);

        assertThat(server.toolCalls("campaigns_get")).extracting(sent -> sent.arguments().path("id").asText())
                .containsOnly("seed");
    }

    @Test
    void neverCallsUnannotatedToolsOrToolsNamedLikeWritesEvenWhenMarkedReadOnly() {
        mine(MiningSettings.defaults(), tools(LIST_CAMPAIGNS, unannotatedTool("campaigns_export", noArguments()),
                readOnlyTool("campaigns_delete", noArguments()), readOnlyTool("updateCampaign", noArguments())), ALICE);

        assertThat(server.sent()).extracting(ScriptedServer.Sent::toolName)
                .contains("campaigns_list").doesNotContain("campaigns_export", "campaigns_delete", "updateCampaign");
    }

    @Test
    void callsAnExplicitlyAllowedWriteToolOnceItsCallsAreApproved() {
        MiningSettings settings = MiningSettings.defaults().withAllowedTools(Set.of("campaigns_export"));

        new AccessMiner(server, settings).mine(tools(unannotatedTool("campaigns_export", noArguments())),
                List.of(ALICE), approving(new ArrayList<>()));

        assertThat(server.toolCalls("campaigns_export")).isNotEmpty();
    }

    @Test
    void anUnattendedRunNeverCallsAWriteTool() {
        MiningSettings settings = MiningSettings.defaults().withAllowedTools(Set.of("campaigns_export"));

        mine(settings, tools(unannotatedTool("campaigns_export", noArguments())), ALICE);

        assertThat(server.toolCalls("campaigns_export")).isEmpty();
    }

    @Test
    void theWriteApprovalListsTheRealIdsEachWriteCallWillReceive() {
        server.tool("alice", "campaigns_list", "{\"campaigns\":[{\"id\":\"" + ALICE_CAMPAIGN + "\"}]}");
        McpToolDefinition archive = unannotatedTool("campaigns_archive", stringArgument("id"));
        List<List<MiningCall.ToolCall>> asked = new ArrayList<>();

        new AccessMiner(server, MiningSettings.defaults().withAllowedTools(Set.of("campaigns_archive")))
                .mine(tools(LIST_CAMPAIGNS, archive), List.of(ALICE), approving(asked));

        assertThat(asked).flatExtracting(calls -> calls)
                .allMatch(call -> call.tool().name().equals("campaigns_archive"))
                .extracting(call -> call.arguments().getOrDefault("id", com.fasterxml.jackson.databind.node.NullNode.getInstance()).asText())
                .contains(ALICE_CAMPAIGN);
        assertThat(server.toolCalls("campaigns_archive")).extracting(sent -> sent.arguments().path("id").asText())
                .contains(ALICE_CAMPAIGN);
    }

    @Test
    void refusedWriteCallsAreSkippedWhileReadOnlyCallsGoAhead() {
        server.tool("alice", "campaigns_list", "{\"campaigns\":[{\"id\":\"" + ALICE_CAMPAIGN + "\"}]}");
        McpToolDefinition archive = unannotatedTool("campaigns_archive", stringArgument("id"));
        List<Integer> asked = new ArrayList<>();

        new AccessMiner(server, MiningSettings.defaults().withAllowedTools(Set.of("campaigns_archive")))
                .mine(tools(LIST_CAMPAIGNS, GET_CAMPAIGN, archive), List.of(ALICE),
                        new MiningControl(MiningProgress.NONE, () -> false, (user, calls) -> !asked.add(calls.size())));

        assertThat(asked).isNotEmpty();
        assertThat(server.toolCalls("campaigns_archive")).isEmpty();
        assertThat(server.toolCalls("campaigns_get")).isNotEmpty();
    }

    @Test
    void readOnlyPassesNeverAskForApproval() {
        server.tool("alice", "campaigns_list", "{\"campaigns\":[{\"id\":\"" + ALICE_CAMPAIGN + "\"}]}");
        List<List<MiningCall.ToolCall>> asked = new ArrayList<>();

        new AccessMiner(server, MiningSettings.defaults()).mine(tools(LIST_CAMPAIGNS, GET_CAMPAIGN), List.of(ALICE),
                approving(asked));

        assertThat(asked).isEmpty();
    }

    private static MiningControl approving(List<List<MiningCall.ToolCall>> asked) {
        return new MiningControl(MiningProgress.NONE, () -> false, (user, calls) -> asked.add(calls));
    }

    @Test
    void sendsEveryMiningCallTwice() {
        mine(MiningSettings.defaults().withPasses(1), tools(LIST_CAMPAIGNS), ALICE);

        assertThat(server.toolCalls("campaigns_list")).filteredOn(sent -> sent.identityId().equals("alice"))
                .hasSize(2);
    }

    @Test
    void laterPassesFeedMinedValuesIntoMatchingArguments() {
        server.tool("alice", "campaigns_list", "{\"campaigns\":[{\"id\":\"" + ALICE_CAMPAIGN + "\"}]}");

        mine(MiningSettings.defaults(), tools(LIST_CAMPAIGNS, GET_CAMPAIGN), ALICE);

        assertThat(server.toolCalls("campaigns_get")).extracting(sent -> sent.arguments().path("id").asText())
                .contains(ALICE_CAMPAIGN);
    }

    @Test
    void aSinglePassFeedsNothing() {
        server.tool("alice", "campaigns_list", "{\"campaigns\":[{\"id\":\"" + ALICE_CAMPAIGN + "\"}]}");

        mine(MiningSettings.defaults().withPasses(1), tools(LIST_CAMPAIGNS, GET_CAMPAIGN), ALICE);

        assertThat(server.toolCalls("campaigns_get")).extracting(sent -> sent.arguments().path("id").asText())
                .doesNotContain(ALICE_CAMPAIGN);
    }

    @Test
    void stopsEarlyWhenAPassFindsNothingNew() {
        server.tool("alice", "campaigns_list", "{\"campaigns\":[{\"id\":\"" + ALICE_CAMPAIGN + "\"}]}");
        List<Integer> passes = new ArrayList<>();

        new AccessMiner(server, MiningSettings.defaults().withPasses(5)).mine(tools(LIST_CAMPAIGNS, GET_CAMPAIGN),
                List.of(ALICE), new MiningControl(step -> passes.add(step.pass()), () -> false));

        assertThat(passes).isNotEmpty().allMatch(pass -> pass <= 2);
    }

    @Test
    void feedsValuesUnderEquivalentArgumentNames() {
        server.tool("alice", "campaigns_list", "{\"campaigns\":[{\"id\":\"" + ALICE_CAMPAIGN + "\"}],"
                + "\"owner\":{\"campaign_id\":\"" + BOB_CAMPAIGN + "\"}}");
        McpToolDefinition camel = readOnlyTool("stats_read", stringArgument("campaignId"));

        mine(MiningSettings.defaults(), tools(LIST_CAMPAIGNS, camel), ALICE);

        assertThat(server.toolCalls("stats_read")).extracting(sent -> sent.arguments().path("campaignId").asText())
                .contains(ALICE_CAMPAIGN, BOB_CAMPAIGN);
    }

    @Test
    void feedsAnIdListedUnderAnObjectsPluralNameIntoThatObjectsOwnArgument() {
        server.tool("alice", "list_vaults", "{\"vaults\":[{\"id\":\"main\",\"name\":\"main\"},"
                + "{\"id\":\"tenantb\",\"name\":\"tenantb\"}]}");
        McpToolDefinition listVaults = unannotatedTool("list_vaults", noArguments());
        McpToolDefinition readNote = unannotatedTool("read_note", stringArgument("vault"));

        mine(MiningSettings.defaults(), tools(listVaults, readNote), ALICE);

        assertThat(server.toolCalls("read_note")).extracting(sent -> sent.arguments().path("vault").asText())
                .contains("main", "tenantb");
    }

    @Test
    void neverMinesValuesFromAnErrorsArrayOfASuccessfulReply() {
        server.tool("alice", "list_notes", "{\"notes\":[{\"path\":\"normal.md\"}]}");
        server.tool("alice", "read_notes", "{\"notes\":[],\"errors\":[{\"path\":\"missing.md\",\"message\":\"not found\"}]}");
        McpToolDefinition listNotes = unannotatedTool("list_notes", noArguments());
        McpToolDefinition readNotes = unannotatedTool("read_notes", stringArgument("path"));

        MiningResult result = mine(MiningSettings.defaults(), tools(listNotes, readNotes), ALICE);

        assertThat(result.of("alice").orElseThrow().values()).extracting(MinedValue::value)
                .contains("normal.md").doesNotContain("missing.md");
    }

    @Test
    void neverMinesAValueTheScannerSentAsAPlaceholderEvenWhenTheReplyEchoesIt() {
        server.on((identity, call) -> call.params().path("name").asText().equals("find_notes")
                ? Optional.of(MiningReply.of(200, structured("{\"query\":{\"path\":\""
                + call.params().path("arguments").path("path").asText() + "\"},\"notes\":[{\"path\":\"normal.md\"}]}")))
                : Optional.empty());
        McpToolDefinition findNotes = unannotatedTool("find_notes", "{\"type\":\"object\",\"properties\":"
                + "{\"path\":{\"type\":\"string\",\"default\":\"test\"}},\"required\":[\"path\"]}");

        MiningResult result = mine(MiningSettings.defaults(), tools(findNotes), ALICE);

        assertThat(result.of("alice").orElseThrow().values()).extracting(MinedValue::value)
                .contains("normal.md").doesNotContain("test");
    }

    @Test
    void feedsAnAttachmentArrayListedInARecordIntoTheArrayArgumentOfTheSameNameFittedToItsSchema() {
        listRecordsWithVolatileSignedPaths();

        MiningResult result = mine(MiningSettings.defaults(), tools(QUERY_RECORDS, READ_ATTACHMENT), ALICE);

        assertThat(server.toolCalls("read_attachment")).extracting(sent -> sent.arguments().path("files"))
                .contains(json("[{\"path\":\"download/a.txt\",\"title\":\"a.txt\",\"mimeType\":\"text/plain\","
                        + "\"size\":35,\"signedPath\":null}]"));
        assertThat(result.of("alice").orElseThrow().values()).extracting(MinedValue::argument).contains("files");
    }

    @Test
    void neverKeepsASignedLinkOfAnAttachmentInAMinedValue() {
        listRecordsWithVolatileSignedPaths();

        MiningResult result = mine(MiningSettings.defaults(), tools(QUERY_RECORDS, READ_ATTACHMENT), ALICE);

        assertThat(result.of("alice").orElseThrow().values()).filteredOn(value -> value.argument().equals("files"))
                .isNotEmpty().allSatisfy(value -> assertThat(value.value()).doesNotContain("dltemp"));
    }

    @Test
    void neverKeepsAPreSignedUrlOfAnAttachmentInAMinedValueOrSendsItBack() {
        server.tool("alice", "query_records", "{\"files\":[{\"path\":\"a.txt\",\"title\":\"a.txt\","
                + "\"download_url\":\"https://bucket.s3.amazonaws.com/f1?X-Amz-Signature=abc&X-Amz-Credential=AKIA\","
                + "\"presignedUrl\":\"https://bucket.s3.amazonaws.com/f1?X-Amz-Signature=abc\"}]}");
        McpToolDefinition readFiles = readOnlyTool("read_attachment", "{\"type\":\"object\",\"properties\":"
                + "{\"files\":{\"type\":\"array\",\"items\":{\"type\":\"object\",\"properties\":"
                + "{\"path\":{\"type\":\"string\"},\"title\":{\"type\":\"string\"},"
                + "\"download_url\":{\"type\":\"string\"},\"presignedUrl\":{\"type\":\"string\"}}}}}}");

        MiningResult result = mine(MiningSettings.defaults(), tools(QUERY_RECORDS, readFiles), ALICE);

        assertThat(result.of("alice").orElseThrow().values()).filteredOn(value -> value.argument().equals("files"))
                .isNotEmpty().allSatisfy(value -> assertThat(value.value()).doesNotContain("Signature", "Credential"));
        assertThat(server.toolCalls("read_attachment")).extracting(sent -> sent.arguments().toString())
                .noneMatch(arguments -> arguments.contains("Signature"));
    }

    @Test
    void storesOnlyTheAttachmentPropertiesTheArgumentDeclares() {
        server.tool("alice", "query_records", "{\"files\":[{\"path\":\"a.txt\",\"owner\":\"alice@example.com\"}]}");
        McpToolDefinition readFiles = readOnlyTool("read_attachment", "{\"type\":\"object\",\"properties\":"
                + "{\"files\":{\"type\":\"array\",\"items\":{\"type\":\"object\",\"properties\":"
                + "{\"path\":{\"type\":\"string\"}}}}}}");

        MiningResult result = mine(MiningSettings.defaults(), tools(QUERY_RECORDS, readFiles), ALICE);

        assertThat(result.of("alice").orElseThrow().values()).filteredOn(value -> value.argument().equals("files"))
                .isNotEmpty().allSatisfy(value -> assertThat(value.value()).contains("a.txt")
                        .doesNotContain("alice@example.com"));
    }

    @Test
    void stillMinesAnIdTheScannerFedIntoACallWhenTheReplyEchoesIt() {
        server.tool("alice", "list_notes", "{\"notes\":[{\"path\":\"normal.md\"}]}");
        server.on((identity, call) -> call.params().path("name").asText().equals("read_notes")
                ? Optional.of(MiningReply.of(200, structured("{\"path\":\""
                + call.params().path("arguments").path("path").asText() + "\",\"related\":[{\"path\":\"normal.md\"}]}")))
                : Optional.empty());
        McpToolDefinition listNotes = unannotatedTool("list_notes", noArguments());
        McpToolDefinition readNotes = unannotatedTool("read_notes", stringArgument("path"));

        MiningResult result = mine(MiningSettings.defaults(), tools(listNotes, readNotes), ALICE);

        assertThat(result.of("alice").orElseThrow().values()).extracting(MinedValue::value).contains("normal.md");
    }

    @Test
    void stillMinesValuesFromAnErrorsArrayThatReportsNoError() {
        server.tool("alice", "list_notes", "{\"errors\":[{\"path\":\"recorded.md\"}]}");
        McpToolDefinition listNotes = unannotatedTool("list_notes", noArguments());
        McpToolDefinition readNotes = unannotatedTool("read_notes", stringArgument("path"));

        MiningResult result = mine(MiningSettings.defaults(), tools(listNotes, readNotes), ALICE);

        assertThat(result.of("alice").orElseThrow().values()).extracting(MinedValue::value).contains("recorded.md");
    }

    @Test
    void doesNotFeedAnArrayWhoseObjectsShareNoPropertyWithTheArgument() {
        server.tool("alice", "query_records", "{\"files\":[{\"colour\":\"red\"}]}");

        mine(MiningSettings.defaults(), tools(QUERY_RECORDS, READ_ATTACHMENT), ALICE);

        assertThat(server.toolCalls("read_attachment")).extracting(sent -> sent.arguments().path("files"))
                .containsOnly(json("[]"));
    }

    @Test
    void extractsJsonEmbeddedInTextContent() {
        server.on((identity, call) -> call.params().path("name").asText().equals("campaigns_list")
                ? Optional.of(MiningReply.of(200, json("{\"content\":[{\"type\":\"text\",\"text\":"
                + "\"{\\\"campaigns\\\":[{\\\"id\\\":\\\"" + ALICE_CAMPAIGN + "\\\"}]}\"}]}")))
                : Optional.empty());

        MiningResult result = mine(MiningSettings.defaults(), tools(LIST_CAMPAIGNS, GET_CAMPAIGN), ALICE);

        assertThat(result.of("alice").orElseThrow().values()).extracting(MinedValue::value).contains(ALICE_CAMPAIGN);
    }

    @Test
    void extractsResourceContents() {
        McpResourceDefinition resource = new McpResourceDefinition("crm://campaigns", "campaigns", "", "application/json");
        server.on((identity, call) -> call.method().equals("resources/read")
                ? Optional.of(MiningReply.of(200, json("{\"contents\":[{\"uri\":\"crm://campaigns\",\"text\":"
                + "\"[{\\\"id\\\":\\\"" + ALICE_CAMPAIGN + "\\\"}]\"}]}")))
                : Optional.empty());

        MiningResult result = mine(MiningSettings.defaults(),
                new ScanInventory(List.of(GET_CAMPAIGN), List.of(resource), List.of(), List.of()), ALICE);

        assertThat(result.of("alice").orElseThrow().values())
                .extracting(MinedValue::value, mined -> mined.source().operation())
                .contains(org.assertj.core.groups.Tuple.tuple(ALICE_CAMPAIGN, "resources/read crm://campaigns"));
    }

    @Test
    void recordsWhereEachValueCameFrom() {
        server.tool("alice", "campaigns_list", "{\"campaigns\":[{\"id\":\"" + ALICE_CAMPAIGN + "\"}]}");

        MiningResult result = mine(MiningSettings.defaults(), tools(LIST_CAMPAIGNS, GET_CAMPAIGN), ALICE);

        assertThat(result.of("alice").orElseThrow().values()).contains(new MinedValue("id", ALICE_CAMPAIGN,
                new MinedSource("tools/call campaigns_list", "structuredContent.campaigns[0].id"), ValueScope.PRIVATE));
    }

    @Test
    void retriesOnceWhenOneOfTheTwoSendsFailsAndKeepsTheValues() {
        failListingSends(Set.of(2));

        MiningResult result = mine(MiningSettings.defaults().withPasses(1), tools(LIST_CAMPAIGNS, GET_CAMPAIGN), ALICE);

        assertThat(result.of("alice").orElseThrow().values()).extracting(MinedValue::value).contains(ALICE_CAMPAIGN);
        assertThat(aliceListings()).hasSize(3);
    }

    @Test
    void dropsTheCallsValuesWhenTheRetryFailsToo() {
        failListingSends(Set.of(2, 3));

        MiningResult result = mine(MiningSettings.defaults().withPasses(1), tools(LIST_CAMPAIGNS, GET_CAMPAIGN), ALICE);

        assertThat(result.of("alice").orElseThrow().values()).extracting(MinedValue::value)
                .doesNotContain(ALICE_CAMPAIGN);
        assertThat(aliceListings()).hasSize(3);
    }

    @Test
    void doesNotRetryWhenBothSendsFail() {
        failListingSends(Set.of(1, 2));

        mine(MiningSettings.defaults().withPasses(1), tools(LIST_CAMPAIGNS, GET_CAMPAIGN), ALICE);

        assertThat(aliceListings()).hasSize(2);
    }

    @Test
    void doesNotRetryPastTheRequestBudget() {
        failListingSends(Set.of(2));

        mine(limits(1, VALUES, 2, PAGES), tools(LIST_CAMPAIGNS, GET_CAMPAIGN), ALICE);

        assertThat(aliceListings()).hasSize(2);
    }

    private void failListingSends(Set<Integer> failing) {
        AtomicInteger sends = new AtomicInteger();
        server.on((identity, call) -> {
            if (!identity.id().equals("alice") || !call.params().path("name").asText().equals("campaigns_list")) {
                return Optional.empty();
            }
            return Optional.of(failing.contains(sends.incrementAndGet()) ? MiningReply.of(502, null)
                    : MiningReply.of(200, structured(campaignsIn(ALICE_CAMPAIGN))));
        });
    }

    private List<ScriptedServer.Sent> aliceListings() {
        return server.toolCalls("campaigns_list").stream().filter(sent -> sent.identityId().equals("alice")).toList();
    }

    @Test
    void ignoresValuesThatDifferBetweenTheTwoSends() {
        server.on((identity, call) -> call.params().path("name").asText().equals("campaigns_list")
                ? Optional.of(MiningReply.of(200, structured("{\"campaigns\":[{\"id\":\"" + UUID.randomUUID() + "\"}]}")))
                : Optional.empty());

        MiningResult result = mine(MiningSettings.defaults(), tools(LIST_CAMPAIGNS, GET_CAMPAIGN), ALICE);

        assertThat(result.of("alice").orElseThrow().values()).isEmpty();
    }

    @Test
    void keepsOnlyIdShapedValuesOfAnArgumentsTypeAndNeverRoutesOrCursors() {
        server.tool("alice", "campaigns_list", "{\"campaigns\":[{\"id\":\"" + ALICE_CAMPAIGN + "\","
                + "\"url\":\"https://crm.example/c/1\",\"path\":\"/etc/passwd\",\"count\":\"many\","
                + "\"archived\":true,\"note\":\"not an argument\",\"size\":\"not a number\"}],"
                + "\"nextCursor\":\"abc123\",\"slug\":\"spring-sale\",\"rank\":7}");
        McpToolDefinition fetch = readOnlyTool("fetch_page", "{\"type\":\"object\",\"properties\":{"
                + "\"url\":{\"type\":\"string\"},\"path\":{\"type\":\"string\"},\"cursor\":{\"type\":\"string\"},"
                + "\"nextCursor\":{\"type\":\"string\"},\"archived\":{\"type\":\"string\"},"
                + "\"size\":{\"type\":\"integer\"},\"slug\":{\"type\":\"string\"},\"rank\":{\"type\":\"integer\"}}}");

        MiningResult result = mine(MiningSettings.defaults(), tools(LIST_CAMPAIGNS, GET_CAMPAIGN, fetch), ALICE);

        assertThat(result.of("alice").orElseThrow().values()).extracting(MinedValue::value)
                .containsExactlyInAnyOrder(ALICE_CAMPAIGN, "spring-sale", "7");
    }

    @Test
    void capsTheValuesKeptAndFedPerArgument() {
        server.tool("alice", "campaigns_list", "{\"campaigns\":[{\"id\":\"a-1\"},{\"id\":\"a-2\"},{\"id\":\"a-3\"}]}");

        MiningResult result = mine(limits(PASSES, 2, REQUESTS, PAGES),
                tools(LIST_CAMPAIGNS, GET_CAMPAIGN), ALICE);

        assertThat(result.of("alice").orElseThrow().values()).hasSize(2);
        assertThat(server.toolCalls("campaigns_get")).extracting(sent -> sent.arguments().path("id").asText())
                .doesNotContain("a-3");
    }

    @Test
    void classifiesValuesOnlyOneIdentitySawAsPrivateAndTheRestAsShared() {
        server.tool("alice", "campaigns_list", campaignsIn(ALICE_CAMPAIGN));
        server.tool("bob", "campaigns_list", campaignsIn(BOB_CAMPAIGN));

        MiningResult result = mine(MiningSettings.defaults(), tools(LIST_CAMPAIGNS, GET_CAMPAIGN), ALICE, BOB);

        assertThat(result.of("alice").orElseThrow().values()).extracting(MinedValue::value, MinedValue::scope)
                .contains(org.assertj.core.groups.Tuple.tuple(ALICE_CAMPAIGN, ValueScope.PRIVATE),
                        org.assertj.core.groups.Tuple.tuple(ORG, ValueScope.SHARED));
    }

    @Test
    void aValueTheAnonymousUserAlsoSawIsShared() {
        server.tool("alice", "campaigns_list", campaignsIn(ALICE_CAMPAIGN));
        server.tool(Principal.ANONYMOUS_ID, "campaigns_list", campaignsIn(ALICE_CAMPAIGN));

        MiningResult result = mine(MiningSettings.defaults(), tools(LIST_CAMPAIGNS, GET_CAMPAIGN), ALICE);

        assertThat(result.of("alice").orElseThrow().privateValues()).isEmpty();
        assertThat(result.of(Principal.ANONYMOUS_ID)).isPresent();
    }

    @Test
    void warnsAboutAnIdentityWhoseMiningFoundNothing() {
        server.tool("alice", "campaigns_list", campaignsIn(ALICE_CAMPAIGN));

        MiningResult result = mine(MiningSettings.defaults(), tools(LIST_CAMPAIGNS, GET_CAMPAIGN), ALICE, BOB);

        assertThat(result.of("bob").orElseThrow().warnings()).extracting(MiningWarning::kind)
                .containsExactly(MiningWarning.Kind.EMPTY);
        assertThat(result.of(Principal.ANONYMOUS_ID).orElseThrow().warnings()).isEmpty();
    }

    @Test
    void warnsAboutTheSameTenantWhenNoUserHasAnyPrivateValue() {
        server.tool("alice", "campaigns_list", "{\"org\":{\"id\":\"" + ORG + "\"}}");
        server.tool("bob", "campaigns_list", "{\"org\":{\"id\":\"" + ORG + "\"}}");

        MiningResult result = mine(MiningSettings.defaults(), tools(LIST_CAMPAIGNS, GET_CAMPAIGN), ALICE, BOB);

        assertThat(result.warnings()).extracting(MiningWarning::kind).containsExactly(MiningWarning.Kind.SAME_TENANT);
    }

    @Test
    void doesNotWarnAboutTheSameTenantWhenUsersHavePrivateValuesBesideSharedOnes() {
        server.tool("alice", "campaigns_list", campaignsIn(ALICE_CAMPAIGN));
        server.tool("bob", "campaigns_list", campaignsIn(BOB_CAMPAIGN));

        MiningResult result = mine(MiningSettings.defaults(), tools(LIST_CAMPAIGNS, GET_CAMPAIGN), ALICE, BOB);

        assertThat(result.warnings()).isEmpty();
    }

    @Test
    void doesNotWarnAboutTheSameTenantWhenNothingWasMined() {
        MiningResult result = mine(MiningSettings.defaults(), tools(LIST_CAMPAIGNS, GET_CAMPAIGN), ALICE, BOB);

        assertThat(result.warnings()).isEmpty();
    }

    @Test
    void doesNotWarnAboutTheSameTenantForASingleUser() {
        server.tool("alice", "campaigns_list", "{\"org\":{\"id\":\"" + ORG + "\"}}");
        server.tool(Principal.ANONYMOUS_ID, "campaigns_list", "{\"org\":{\"id\":\"" + ORG + "\"}}");

        MiningResult result = mine(MiningSettings.defaults(), tools(LIST_CAMPAIGNS, GET_CAMPAIGN), ALICE);

        assertThat(result.warnings()).isEmpty();
    }

    @Test
    void stopsAnIdentityAtItsRequestLimit() {
        MiningResult result = mine(limits(PASSES, VALUES, 4, PAGES),
                tools(readOnlyTool("a_list", noArguments()), readOnlyTool("b_list", noArguments()),
                        readOnlyTool("c_list", noArguments())), ALICE);

        assertThat(server.sent()).filteredOn(sent -> sent.identityId().equals("alice")).hasSize(4);
        assertThat(result.of("alice").orElseThrow().requestsSent()).isEqualTo(4);
        assertThat(result.of("alice").orElseThrow().warnings()).extracting(MiningWarning::kind)
                .contains(MiningWarning.Kind.REQUEST_LIMIT);
    }

    @Test
    void stopsTheWholeRunOnTooManyRequests() {
        server.on((identity, call) -> Optional.of(MiningReply.of(429, null)));

        MiningResult result = mine(MiningSettings.defaults(), tools(LIST_CAMPAIGNS, GET_CAMPAIGN), ALICE, BOB);

        assertThat(result.stop()).isEqualTo(MiningStop.RATE_LIMITED);
        assertThat(server.sent()).hasSize(1);
    }

    @Test
    void stopsWhenCancelled() {
        AtomicInteger checks = new AtomicInteger();

        MiningResult result = new AccessMiner(server, MiningSettings.defaults()).mine(
                tools(LIST_CAMPAIGNS, GET_CAMPAIGN), List.of(ALICE, BOB),
                new MiningControl(MiningProgress.NONE, () -> checks.incrementAndGet() > 1));

        assertThat(result.stop()).isEqualTo(MiningStop.CANCELLED);
        assertThat(server.sent()).hasSize(2);
    }

    @Test
    void reportsProgressAfterEachCall() {
        List<MiningStep> steps = new ArrayList<>();

        new AccessMiner(server, MiningSettings.defaults()).mine(tools(LIST_CAMPAIGNS), List.of(ALICE),
                new MiningControl(steps::add, () -> false));

        assertThat(steps).first().isEqualTo(new MiningStep("alice", 1, 2));
    }

    @Test
    void minesListedResourcesAndTheirTemplateVariablesPerIdentity() {
        McpResourceTemplateDefinition notes = new McpResourceTemplateDefinition("notes://{noteId}", "note", "", null);
        McpToolDefinition readNote = readOnlyTool("note_read", stringArgument("noteId"));
        server.on((identity, call) -> identity.id().equals("alice") && call.method().equals("resources/list")
                ? Optional.of(MiningReply.of(200, json("{\"resources\":[{\"uri\":\"notes://n-a11ce\",\"name\":\"n\"}]}")))
                : Optional.empty());

        MiningResult result = mine(MiningSettings.defaults(),
                new ScanInventory(List.of(readNote), List.of(), List.of(notes), List.of()), ALICE);

        assertThat(result.of("alice").orElseThrow().values()).extracting(MinedValue::argument, MinedValue::value)
                .contains(org.assertj.core.groups.Tuple.tuple("noteId", "n-a11ce"),
                        org.assertj.core.groups.Tuple.tuple("uri", "notes://n-a11ce"));
        assertThat(server.sent()).extracting(sent -> sent.call().params().path("uri").asText())
                .contains("notes://n-a11ce");
        assertThat(server.toolCalls("note_read")).extracting(sent -> sent.arguments().path("noteId").asText())
                .contains("n-a11ce").doesNotContain("notes://n-a11ce");
    }

    @Test
    void templateOperatorsNeverReachAMinedArgumentName() {
        McpResourceTemplateDefinition plain = new McpResourceTemplateDefinition("file:///{path}", "f", "", null);
        McpResourceTemplateDefinition encoded = new McpResourceTemplateDefinition("encoded-file:///{+path}", "e", "",
                null);
        server.on((identity, call) -> call.method().equals("resources/list")
                ? Optional.of(MiningReply.of(200, json("{\"resources\":[{\"uri\":\"file:///readme-0001.txt\"},"
                        + "{\"uri\":\"encoded-file:///readme-0001.txt\"}]}")))
                : Optional.empty());

        MiningResult result = mine(MiningSettings.defaults(),
                new ScanInventory(List.of(), List.of(), List.of(plain, encoded), List.of()), ALICE);

        assertThat(result.of("alice").orElseThrow().values()).extracting(MinedValue::argument)
                .contains("path").noneMatch(argument -> argument.startsWith("+"));
        assertThat(result.of("alice").orElseThrow().values())
                .filteredOn(value -> value.argument().equals("path"))
                .extracting(MinedValue::value).containsExactly("readme-0001.txt");
    }

    @Test
    void followsResourceListingCursorsToLaterPages() {
        server.on((identity, call) -> call.method().equals("resources/list") ? Optional.of(MiningReply.of(200,
                json(page(call.params().path("cursor").asText(""))))) : Optional.empty());

        MiningResult result = mine(MiningSettings.defaults(), tools(LIST_CAMPAIGNS), ALICE);

        assertThat(result.of("alice").orElseThrow().values()).extracting(MinedValue::value)
                .contains("notes://page-1", "notes://page-2", "notes://page-3");
        assertThat(aliceSent()).filteredOn(sent -> sent.call().method().equals("resources/list"))
                .extracting(sent -> sent.call().params().path("cursor").asText(""))
                .containsExactly("", "", "c2", "c2", "c3", "c3");
        assertThat(result.of("alice").orElseThrow().values())
                .filteredOn(value -> value.value().equals("notes://page-3"))
                .extracting(value -> value.source().operation()).containsOnly("resources/list (page 3)");
    }

    @Test
    void stopsFollowingCursorsAtThePageCap() {
        server.on((identity, call) -> call.method().equals("resources/list") ? Optional.of(MiningReply.of(200,
                json(endless(call.params().path("cursor").asText("c0"))))) : Optional.empty());

        mine(limits(PASSES, VALUES, REQUESTS, 3), tools(), ALICE);

        assertThat(aliceSent()).filteredOn(sent -> sent.call().method().equals("resources/list")).hasSize(6);
    }

    @Test
    void listingPagesCountAgainstTheRequestBudget() {
        server.on((identity, call) -> call.method().equals("resources/list") ? Optional.of(MiningReply.of(200,
                json(endless(call.params().path("cursor").asText("c0"))))) : Optional.empty());

        MiningResult result = mine(limits(PASSES, VALUES, 8, PAGES), tools(), ALICE);

        assertThat(aliceSent()).hasSize(8);
        assertThat(result.of("alice").orElseThrow().warnings()).extracting(MiningWarning::kind)
                .contains(MiningWarning.Kind.REQUEST_LIMIT);
    }

    @Test
    void aCursorThatRepeatsIsNotFollowedTwice() {
        server.on((identity, call) -> call.method().equals("resources/list") ? Optional.of(MiningReply.of(200,
                json("{\"resources\":[],\"nextCursor\":\"same\"}"))) : Optional.empty());

        mine(MiningSettings.defaults(), tools(), ALICE);

        assertThat(aliceSent()).filteredOn(sent -> sent.call().method().equals("resources/list")).hasSize(4);
    }

    private List<ScriptedServer.Sent> aliceSent() {
        return server.sent().stream().filter(sent -> sent.identityId().equals("alice")).toList();
    }

    private static String page(String cursor) {
        int number = cursor.isEmpty() ? 1 : Integer.parseInt(cursor.substring(1));
        String next = number < 3 ? ",\"nextCursor\":\"c" + (number + 1) + "\"" : "";
        return "{\"resources\":[{\"uri\":\"notes://page-" + number + "\",\"name\":\"n\"}]" + next + "}";
    }

    private static String endless(String cursor) {
        int number = Integer.parseInt(cursor.substring(1));
        return "{\"resources\":[{\"uri\":\"notes://p" + number + "\"}],\"nextCursor\":\"c" + (number + 1) + "\"}";
    }

    @Test
    void feedsMinedValuesIntoResourceTemplates() {
        McpResourceTemplateDefinition campaign = new McpResourceTemplateDefinition("crm://campaigns/{campaign_id}",
                "campaign", "", null);
        server.tool("alice", "campaigns_list", campaignsIn(ALICE_CAMPAIGN));

        mine(MiningSettings.defaults(), new ScanInventory(List.of(LIST_CAMPAIGNS), List.of(), List.of(campaign),
                List.of()), ALICE);

        assertThat(server.sent()).extracting(sent -> sent.call().params().path("uri").asText())
                .contains("crm://campaigns/" + ALICE_CAMPAIGN);
    }

    @Test
    void firstPassOmitsOptionalArgumentsThatHaveNoSchemaDefault() {
        McpToolDefinition search = readOnlyTool("projects_list", "{\"type\":\"object\",\"required\":[\"scope\"],"
                + "\"properties\":{\"scope\":{\"type\":\"string\"},\"search\":{\"type\":\"string\"},"
                + "\"archived\":{\"type\":\"boolean\",\"default\":false}}}");

        mine(MiningSettings.defaults().withPasses(1), tools(search), ALICE);

        assertThat(server.toolCalls("projects_list")).extracting(sent -> sent.arguments().toString())
                .containsOnly("{\"archived\":false,\"scope\":\"test\"}");
    }

    @Test
    void namesAWrappedResultAfterTheToolThatReturnedIt() {
        McpToolDefinition listNotes = readOnlyTool("list_my_notes", noArguments());
        McpToolDefinition getNote = readOnlyTool("get_note", stringArgument("note_id"));
        server.tool("alice", "list_my_notes", "{\"result\":[\"note-alice-1\"]}");

        MiningResult result = mine(MiningSettings.defaults(), tools(listNotes, getNote), ALICE);

        assertThat(result.of("alice").orElseThrow().values()).extracting(MinedValue::argument, MinedValue::value)
                .contains(org.assertj.core.groups.Tuple.tuple("note_id", "note-alice-1"));
        assertThat(server.toolCalls("get_note")).extracting(sent -> sent.arguments().path("note_id").asText())
                .contains("note-alice-1");
    }

    @Test
    void dropsPaginationOffsetsAndLimits() {
        server.tool("alice", "campaigns_list", "{\"offset\":0,\"limit\":20,\"page\":1}");
        McpToolDefinition paged = readOnlyTool("campaigns_page", "{\"type\":\"object\",\"properties\":{"
                + "\"offset\":{\"type\":\"integer\"},\"limit\":{\"type\":\"integer\"},\"page\":{\"type\":\"integer\"}}}");

        MiningResult result = mine(MiningSettings.defaults(), tools(LIST_CAMPAIGNS, paged), ALICE);

        assertThat(result.of("alice").orElseThrow().values()).isEmpty();
    }

    @Test
    void namesARootLevelIdAfterTheToolThatListedIt() {
        McpToolDefinition listProjects = readOnlyTool("list_projects", noArguments());
        McpToolDefinition getProject = readOnlyTool("get_project", stringArgument("project_id"));
        server.on((identity, call) -> call.params().path("name").asText().equals("list_projects")
                ? Optional.of(MiningReply.of(200, json("{\"content\":[{\"type\":\"text\",\"text\":"
                + "\"[{\\\"id\\\":\\\"9101\\\"}]\"}]}"))) : Optional.empty());

        mine(MiningSettings.defaults(), tools(listProjects, getProject), ALICE);

        assertThat(server.toolCalls("get_project")).extracting(sent -> sent.arguments().path("project_id").asText())
                .contains("9101");
    }

    @Test
    void aValueAnotherUserSawPastTheirCapIsStillShared() {
        server.tool("alice", "campaigns_list", "{\"campaigns\":[{\"id\":\"a-1\"},{\"id\":\"both-1\"}]}");
        server.tool("bob", "campaigns_list", "{\"campaigns\":[{\"id\":\"both-1\"}]}");

        MiningResult result = mine(limits(1, 1, REQUESTS, PAGES),
                tools(LIST_CAMPAIGNS, GET_CAMPAIGN), ALICE, BOB);

        assertThat(result.of("alice").orElseThrow().values()).extracting(MinedValue::value).containsExactly("a-1");
        assertThat(result.of("bob").orElseThrow().values()).extracting(MinedValue::value, MinedValue::scope)
                .containsExactly(org.assertj.core.groups.Tuple.tuple("both-1", ValueScope.SHARED));
    }

    @Test
    void theSameValueUnderDifferentArgumentsIsClassifiedPerArgument() {
        McpToolDefinition listProjects = readOnlyTool("projects_list", noArguments());
        McpToolDefinition getProject = readOnlyTool("projects_get", stringArgument("project_id"));
        server.tool("alice", "campaigns_list", "{\"campaigns\":[{\"id\":\"x-7\"}]}");
        server.tool("bob", "projects_list", "{\"projects\":[{\"id\":\"x-7\"}]}");

        MiningResult result = mine(MiningSettings.defaults().withPasses(1),
                tools(LIST_CAMPAIGNS, listProjects, GET_CAMPAIGN, getProject), ALICE, BOB);

        assertThat(result.of("bob").orElseThrow().values())
                .extracting(MinedValue::argument, MinedValue::value, MinedValue::scope)
                .contains(org.assertj.core.groups.Tuple.tuple("project_id", "x-7", ValueScope.PRIVATE),
                        org.assertj.core.groups.Tuple.tuple("id", "x-7", ValueScope.SHARED));
    }

    @Test
    void neverMinesOrFeedsValuesWhoseKeyLooksLikeASecret() {
        server.tool("alice", "campaigns_list", "{\"campaigns\":[{\"id\":\"" + ALICE_CAMPAIGN + "\","
                + "\"api_key\":\"k-123\",\"accessToken\":\"t-1\",\"password\":\"hunter2\","
                + "\"session\":{\"id\":\"s-1\"},\"cookie\":\"c-1\"}]}");
        McpToolDefinition keys = readOnlyTool("keys_get", "{\"type\":\"object\",\"properties\":{"
                + "\"api_key\":{\"type\":\"string\"},\"accessToken\":{\"type\":\"string\"},"
                + "\"password\":{\"type\":\"string\"},\"session_id\":{\"type\":\"string\"},"
                + "\"cookie\":{\"type\":\"string\"},\"token_id\":{\"type\":\"string\"}}}");

        MiningResult result = mine(MiningSettings.defaults(), tools(LIST_CAMPAIGNS, GET_CAMPAIGN, keys), ALICE);

        assertThat(result.of("alice").orElseThrow().values()).extracting(MinedValue::value)
                .containsOnly(ALICE_CAMPAIGN);
        assertThat(server.toolCalls("keys_get")).allSatisfy(sent ->
                assertThat(sent.arguments().toString()).doesNotContain(ALICE_CAMPAIGN, "k-123", "t-1", "s-1"));
    }

    @Test
    void minesKeyNamedIdsButNotKeySecrets() {
        McpToolDefinition listIssues = readOnlyTool("issues_list", noArguments());
        McpToolDefinition getIssue = readOnlyTool("issues_get", "{\"type\":\"object\",\"properties\":{"
                + "\"issue_key\":{\"type\":\"string\"},\"project_key\":{\"type\":\"string\"},"
                + "\"api_key\":{\"type\":\"string\"},\"accessKey\":{\"type\":\"string\"}}}");
        server.tool("alice", "issues_list", "{\"issues\":[{\"issue_key\":\"PROJ-1\",\"project_key\":\"PROJ\","
                + "\"api_key\":\"k-123\",\"accessKey\":\"a-123\"}]}");

        MiningResult result = mine(MiningSettings.defaults(), tools(listIssues, getIssue), ALICE);

        assertThat(result.of("alice").orElseThrow().values()).extracting(MinedValue::argument, MinedValue::value)
                .containsExactlyInAnyOrder(org.assertj.core.groups.Tuple.tuple("issue_key", "PROJ-1"),
                        org.assertj.core.groups.Tuple.tuple("project_key", "PROJ"));
    }

    @Test
    void aRecordBothUsersSeeIsAttributedToTheUserWhoseMarkerItCarriesAndSharedForTheOther() {
        String everyCampaign = "{\"campaigns\":[{\"id\":\"" + ALICE_CAMPAIGN + "\",\"name\":\"ALICE_ONLY_MARKER\"},"
                + "{\"id\":\"" + BOB_CAMPAIGN + "\",\"name\":\"BOB_ONLY_MARKER\"}]}";
        server.tool("alice", "campaigns_list", everyCampaign);
        server.tool("bob", "campaigns_list", everyCampaign);

        MiningResult result = mine(MiningSettings.defaults(), tools(LIST_CAMPAIGNS, GET_CAMPAIGN),
                withMarker("alice", "ALICE_ONLY_MARKER"), withMarker("bob", "BOB_ONLY_MARKER"));

        assertThat(scopesOf(result, "alice", "id")).containsEntry(ALICE_CAMPAIGN, ValueScope.ATTRIBUTED)
                .containsEntry(BOB_CAMPAIGN, ValueScope.SHARED);
        assertThat(scopesOf(result, "bob", "id")).containsEntry(BOB_CAMPAIGN, ValueScope.ATTRIBUTED)
                .containsEntry(ALICE_CAMPAIGN, ValueScope.SHARED);
    }

    @Test
    void ownerFieldsOnRecordsEveryUserSeesAreNotEvidenceOfPrivacy() {
        String everyCampaign = "{\"campaigns\":[{\"id\":\"" + ALICE_CAMPAIGN + "\",\"createdBy\":\"alice\"},"
                + "{\"id\":\"" + BOB_CAMPAIGN + "\",\"createdBy\":\"bob\"}]}";
        server.tool("alice", "campaigns_list", everyCampaign);
        server.tool("bob", "campaigns_list", everyCampaign);

        MiningResult result = mine(MiningSettings.defaults(), tools(LIST_CAMPAIGNS, GET_CAMPAIGN), ALICE, BOB);

        assertThat(scopesOf(result, "alice", "id").values()).containsOnly(ValueScope.SHARED);
        assertThat(scopesOf(result, "bob", "id").values()).containsOnly(ValueScope.SHARED);
        assertThat(result.of("alice").orElseThrow().privateValues()).isEmpty();
        assertThat(result.of("bob").orElseThrow().privateValues()).isEmpty();
    }

    @Test
    void aRecordWhoseAssigneeIsTheUserButWhoseOwnerIsAnotherIsNotAttributedToTheAssignee() {
        String everyCampaign = "{\"campaigns\":[{\"id\":\"" + BOB_CAMPAIGN + "\",\"owner\":\"bob\","
                + "\"assignee\":\"alice\"}]}";
        server.tool("alice", "campaigns_list", everyCampaign);
        server.tool("bob", "campaigns_list", everyCampaign);

        MiningResult result = mine(MiningSettings.defaults(), tools(LIST_CAMPAIGNS, GET_CAMPAIGN), ALICE, BOB);

        assertThat(scopesOf(result, "alice", "id")).containsEntry(BOB_CAMPAIGN, ValueScope.SHARED);
    }

    @Test
    void aSharedTeamIdBesideTheUsernameInAWhoamiReplyIsNotAttributedToTheUser() {
        server.tool("alice", "campaigns_list", "{\"username\":\"alice\",\"id\":\"" + ALICE_CAMPAIGN + "\"}");
        server.tool("bob", "campaigns_list", "{\"username\":\"bob\",\"id\":\"" + ALICE_CAMPAIGN + "\"}");

        MiningResult result = mine(MiningSettings.defaults(), tools(LIST_CAMPAIGNS, GET_CAMPAIGN), ALICE, BOB);

        assertThat(scopesOf(result, "alice", "id").values()).containsOnly(ValueScope.SHARED);
    }

    @Test
    void recordsEveryUserSeesWithNothingNamingAnOwnerAreSharedForEveryone() {
        String everyProject = "{\"campaigns\":[{\"id\":\"p-1\",\"name\":\"Roadmap\"},{\"id\":\"p-2\",\"name\":\"Plan\"}]}";
        server.tool("alice", "campaigns_list", everyProject);
        server.tool("bob", "campaigns_list", everyProject);

        MiningResult result = mine(MiningSettings.defaults(), tools(LIST_CAMPAIGNS, GET_CAMPAIGN),
                withMarker("alice", "ALICE_ONLY_MARKER"), withMarker("bob", "BOB_ONLY_MARKER"));

        assertThat(scopesOf(result, "alice", "id").values()).containsOnly(ValueScope.SHARED);
        assertThat(result.of("alice").orElseThrow().privateValues()).isEmpty();
    }

    @Test
    void aSharedTemplateReferencedByARecordCarryingAPrivateMarkerIsNotAttributedToTheUser() {
        String everyCampaign = "{\"campaigns\":[{\"id\":\"c-a\",\"name\":\"ALICE_ONLY_MARKER\","
                + "\"template_id\":\"t1\"}]}";
        server.tool("alice", "campaigns_list", everyCampaign);
        server.tool("bob", "campaigns_list", everyCampaign);
        McpToolDefinition getTemplate = readOnlyTool("templates_get", stringArgument("template_id"));

        MiningResult result = mine(MiningSettings.defaults(), tools(LIST_CAMPAIGNS, GET_CAMPAIGN, getTemplate),
                withMarker("alice", "ALICE_ONLY_MARKER"), withMarker("bob", "BOB_ONLY_MARKER"));

        assertThat(scopesOf(result, "alice", "id")).containsEntry("c-a", ValueScope.ATTRIBUTED);
        assertThat(scopesOf(result, "alice", "template_id")).containsEntry("t1", ValueScope.SHARED);
        assertThat(result.of("alice").orElseThrow().privateValues())
                .extracting(MinedValue::argument).doesNotContain("template_id");
        assertThat(result.of("bob").orElseThrow().privateValues()).isEmpty();
    }

    @Test
    void aValueBothUsersMarkersAttributeIsSharedForBoth() {
        String everyCampaign = "{\"campaigns\":[{\"id\":\"c-a\",\"name\":\"ALICE_ONLY_MARKER BOB_ONLY_MARKER\"}]}";
        server.tool("alice", "campaigns_list", everyCampaign);
        server.tool("bob", "campaigns_list", everyCampaign);

        MiningResult result = mine(MiningSettings.defaults(), tools(LIST_CAMPAIGNS, GET_CAMPAIGN),
                withMarker("alice", "ALICE_ONLY_MARKER"), withMarker("bob", "BOB_ONLY_MARKER"));

        assertThat(scopesOf(result, "alice", "id").values()).containsOnly(ValueScope.SHARED);
        assertThat(scopesOf(result, "bob", "id").values()).containsOnly(ValueScope.SHARED);
        assertThat(result.of("alice").orElseThrow().privateValues()).isEmpty();
        assertThat(result.of("bob").orElseThrow().privateValues()).isEmpty();
    }

    @Test
    void aForeignKeyInRecordsCarryingEitherUsersMarkerIsSharedForBothUsers() {
        String everything = "{\"campaigns\":[{\"id\":\"c-a\",\"name\":\"ALICE_ONLY_MARKER BOB_ONLY_MARKER\","
                + "\"template_id\":\"t1\"},{\"id\":\"c-b\",\"name\":\"BOB_ONLY_MARKER\",\"template_id\":\"t1\"}]}";
        server.tool("alice", "campaigns_list", everything);
        server.tool("bob", "campaigns_list", everything);
        McpToolDefinition getTemplate = readOnlyTool("templates_get", stringArgument("template_id"));

        MiningResult result = mine(MiningSettings.defaults(), tools(LIST_CAMPAIGNS, GET_CAMPAIGN, getTemplate),
                withMarker("alice", "ALICE_ONLY_MARKER"), withMarker("bob", "BOB_ONLY_MARKER"));

        assertThat(scopesOf(result, "alice", "template_id").values()).containsOnly(ValueScope.SHARED);
        assertThat(scopesOf(result, "bob", "template_id").values()).containsOnly(ValueScope.SHARED);
        assertThat(result.of("alice").orElseThrow().privateValues()).extracting(MinedValue::argument)
                .doesNotContain("template_id");
        assertThat(result.of("bob").orElseThrow().privateValues()).extracting(MinedValue::argument)
                .doesNotContain("template_id");
    }

    private static Principal withMarker(String id, String marker) {
        return new Principal(id, id, PrincipalRole.PEER, Map::of, Optional.of(marker), Map.of());
    }

    private static Map<String, ValueScope> scopesOf(MiningResult result, String identity, String argument) {
        Map<String, ValueScope> scopes = new java.util.LinkedHashMap<>();
        result.of(identity).orElseThrow().values().stream().filter(value -> value.argument().equals(argument))
                .forEach(value -> scopes.put(value.value(), value.scope()));
        return scopes;
    }

    private static String campaignsIn(String campaign) {
        return "{\"org\":{\"id\":\"" + ORG + "\"},\"campaigns\":[{\"id\":\"" + campaign + "\"}]}";
    }

    private static MiningSettings limits(int passes, int valuesPerArgument, int requestsPerIdentity, int listPages) {
        return new MiningSettings(passes, valuesPerArgument, requestsPerIdentity, listPages, Set.of());
    }

    private void listRecordsWithVolatileSignedPaths() {
        AtomicInteger signings = new AtomicInteger();
        server.on((identity, call) -> call.params().path("name").asText().equals("query_records")
                ? Optional.of(MiningReply.of(200, structured("{\"records\":[{\"id\":1,\"fields\":{\"files\":["
                + "{\"path\":\"download/a.txt\",\"title\":\"a.txt\",\"mimetype\":\"text/plain\",\"size\":35,"
                + "\"id\":\"att1\",\"signedPath\":\"dltemp/" + signings.incrementAndGet() + "/a.txt\"}]}}]}")))
                : Optional.empty());
    }

    private MiningResult mine(MiningSettings settings, ScanInventory catalog, Principal... identities) {
        return new AccessMiner(server, settings).mine(catalog, List.of(identities), MiningControl.unattended());
    }

    private static ScanInventory tools(McpToolDefinition... tools) {
        return ScanInventory.toolsOnly(List.of(tools));
    }
}
