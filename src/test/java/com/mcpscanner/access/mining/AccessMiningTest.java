package com.mcpscanner.access.mining;

import com.mcpscanner.auth.BearerTokenAuthStrategy;
import com.mcpscanner.config.ExtensionConfigStore;
import com.mcpscanner.identity.Identity;
import com.mcpscanner.identity.IdentityAuthKind;
import com.mcpscanner.identity.IdentityRegistry;
import com.mcpscanner.identity.IdentityRole;
import com.mcpscanner.identity.IdentityRosterSource;
import com.mcpscanner.identity.IdentityStore;
import com.mcpscanner.identity.EnteredValue;
import com.mcpscanner.identity.MinedValue;
import com.mcpscanner.identity.RegistryOwnedValues;
import com.mcpscanner.identity.ValueScope;
import com.mcpscanner.logging.McpEventLog;
import com.mcpscanner.mcp.McpToolDefinition;
import com.mcpscanner.scan.ScanInventory;
import com.mcpscanner.testutil.InMemoryPersistedObject;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Optional;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;

import static com.mcpscanner.access.mining.ScriptedServer.noArguments;
import static com.mcpscanner.access.mining.ScriptedServer.readOnlyTool;
import static com.mcpscanner.access.mining.ScriptedServer.stringArgument;
import static com.mcpscanner.access.mining.ScriptedServer.structured;
import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;

class AccessMiningTest {

    private static final McpToolDefinition LIST_DOCUMENTS = readOnlyTool("list_documents", noArguments());
    private static final ScanInventory INVENTORY = ScanInventory.toolsOnly(List.of(LIST_DOCUMENTS,
            readOnlyTool("get_document", stringArgument("doc_id")), readOnlyTool("get_org", stringArgument("org_id"))));

    private final ExtensionConfigStore config = InMemoryPersistedObject.configStore();
    private final IdentityRegistry registry = new IdentityRegistry(new IdentityStore(config, mock(McpEventLog.class)));
    private final RegistryOwnedValues store = new RegistryOwnedValues(registry);
    private final ScriptedServer server = new ScriptedServer();
    private final ExecutorService worker = Executors.newSingleThreadExecutor();
    private final ExecutorService sendWorkers = Executors.newFixedThreadPool(4);
    private final AtomicReference<Optional<ScanInventory>> inventory = new AtomicReference<>(Optional.of(INVENTORY));
    private Identity alice;
    private Identity bob;
    private AccessMining mining;

    @BeforeEach
    void setUp() {
        alice = registry.primaryUser();
        registry.update(alice.withName("alice"));
        bob = registry.add(Identity.create("bob", IdentityRole.PEER, IdentityAuthKind.BEARER).withCompared(true));
        registry.setCredential(bob.id(), new BearerTokenAuthStrategy("bob-token"));
        server.on((identity, call) -> Optional.of(MiningReply.of(200, structured(documentsFor(identity.name())))));
        mining = new AccessMining(new MiningInputs(inventory::get,
                new IdentityRosterSource(() -> new BearerTokenAuthStrategy("alice-token"), registry),
                () -> registry.primaryUser().id()), server, new MiningPreferences(config), store, worker,
                () -> sendWorkers, McpEventLog.noop());
    }

    @AfterEach
    void tearDown() {
        worker.shutdownNow();
        sendWorkers.shutdownNow();
    }

    @Test
    void storesEachUsersMinedValuesUnderTheirOwnIdentity() throws Exception {
        MiningReport report = runToCompletion(WriteCallApproval.REFUSE);

        assertThat(report.stop()).isEqualTo(MiningStop.COMPLETED);
        assertThat(store.valuesOf(alice.id()).mined()).extracting(MinedValue::value, MinedValue::scope)
                .contains(org.assertj.core.groups.Tuple.tuple("d-alice-0001", ValueScope.PRIVATE),
                        org.assertj.core.groups.Tuple.tuple("org-1", ValueScope.SHARED));
        assertThat(store.valuesOf(bob.id()).mined()).extracting(MinedValue::value)
                .contains("d-bob-0042").doesNotContain("d-alice-0001");
    }

    @Test
    void miningReplacesEarlierMinedValuesButKeepsEnteredOnes() throws Exception {
        store.replaceEntered(alice.id(), List.of(new EnteredValue("doc_id", "typed")));
        store.replaceMined(alice.id(), List.of(new MinedValue("doc_id", "stale",
                new com.mcpscanner.identity.MinedSource("tools/call x", "y"), ValueScope.PRIVATE)));

        runToCompletion(WriteCallApproval.REFUSE);

        assertThat(store.valuesOf(alice.id()).entered()).containsExactly(new EnteredValue("doc_id", "typed"));
        assertThat(store.valuesOf(alice.id()).mined()).extracting(MinedValue::value).doesNotContain("stale");
    }

    @Test
    void remembersWhetherTheCurrentIdentitySetHasBeenMined() throws Exception {
        assertThat(mining.minedForCurrentIdentities()).isFalse();

        runToCompletion(WriteCallApproval.REFUSE);
        assertThat(mining.minedForCurrentIdentities()).isTrue();

        Identity carol = registry.add(Identity.create("carol", IdentityRole.LOWER, IdentityAuthKind.BEARER)
                .withCompared(true));
        registry.setCredential(carol.id(), new BearerTokenAuthStrategy("carol-token"));
        assertThat(mining.minedForCurrentIdentities()).isFalse();
    }

    @Test
    void disconnectForgetsThatMiningRan() throws Exception {
        runToCompletion(WriteCallApproval.REFUSE);

        mining.reset();

        assertThat(mining.minedForCurrentIdentities()).isFalse();
    }

    @Test
    void aResetStartsANewConnection() {
        long before = mining.connection();

        mining.reset();

        assertThat(mining.connection()).isNotEqualTo(before);
    }

    @Test
    void listsTheConnectedServersTools() {
        assertThat(mining.tools()).extracting(McpToolDefinition::name)
                .containsExactly("list_documents", "get_document", "get_org");

        inventory.set(Optional.empty());
        assertThat(mining.tools()).isEmpty();
    }

    @Test
    void runsOneMiningAtATime() throws Exception {
        CountDownLatch release = new CountDownLatch(1);
        ScriptedServer blocked = new ScriptedServer().on((identity, call) -> {
            await(release);
            return Optional.of(MiningReply.of(200, structured("{}")));
        });
        AccessMining slow = new AccessMining(new MiningInputs(inventory::get,
                new IdentityRosterSource(() -> new BearerTokenAuthStrategy("alice-token"), registry),
                () -> registry.primaryUser().id()), blocked, new MiningPreferences(config), store, worker,
                () -> sendWorkers, McpEventLog.noop());

        assertThat(slow.start(MiningListener.NONE, WriteCallApproval.REFUSE)).isPresent();
        assertThat(slow.running()).isTrue();
        assertThat(slow.blocker()).contains(MiningBlocker.RUNNING);
        assertThat(slow.start(MiningListener.NONE, WriteCallApproval.REFUSE)).isEmpty();
        release.countDown();
    }

    @Test
    void cancellingStopsTheRunAndStoresNothing() throws Exception {
        CountDownLatch started = new CountDownLatch(1);
        CountDownLatch release = new CountDownLatch(1);
        ScriptedServer blocked = new ScriptedServer().on((identity, call) -> {
            started.countDown();
            await(release);
            return Optional.of(MiningReply.of(200, structured(documentsFor(identity.name()))));
        });
        AccessMining slow = new AccessMining(new MiningInputs(inventory::get,
                new IdentityRosterSource(() -> new BearerTokenAuthStrategy("alice-token"), registry),
                () -> registry.primaryUser().id()), blocked, new MiningPreferences(config), store, worker,
                () -> sendWorkers, McpEventLog.noop());
        CompletableFuture<MiningReport> finished = new CompletableFuture<>();

        slow.start(listener(finished), WriteCallApproval.REFUSE);
        assertThat(started.await(5, TimeUnit.SECONDS)).isTrue();
        slow.reset();
        release.countDown();

        assertThat(finished.get(5, TimeUnit.SECONDS).stop()).isEqualTo(MiningStop.CANCELLED);
        assertThat(store.valuesOf(alice.id()).mined()).isEmpty();
        assertThat(slow.minedForCurrentIdentities()).isFalse();
        assertThat(slow.running()).isFalse();
    }

    @Test
    void aRateLimitedRunSavesNothingAndDoesNotCountAsMined() throws Exception {
        AccessMining limited = miningWith(new ScriptedServer().on((identity, call) -> Optional.of(
                identity.name().equals("bob") ? MiningReply.of(429, null)
                        : MiningReply.of(200, structured(documentsFor(identity.name()))))));

        MiningReport report = runToCompletion(limited);

        assertThat(report.stop()).isEqualTo(MiningStop.RATE_LIMITED);
        assertThat(report.summary()).isEqualTo("Collecting stopped: the server rate-limited the requests; nothing was saved");
        assertThat(store.valuesOf(alice.id()).mined()).isEmpty();
        assertThat(limited.minedForCurrentIdentities()).isFalse();
    }

    @Test
    void aFailedRunHasItsOwnStopAndSavesNothing() throws Exception {
        AccessMining failing = miningWith(new ScriptedServer().on((identity, call) -> {
            throw new IllegalStateException("boom");
        }));

        MiningReport report = runToCompletion(failing);

        assertThat(report.stop()).isEqualTo(MiningStop.FAILED);
        assertThat(report.summary()).isEqualTo("Collecting failed; nothing was saved");
        assertThat(report.warnings()).containsExactly("collecting failed: boom");
        assertThat(failing.minedForCurrentIdentities()).isFalse();
    }

    @Test
    void asksAboutWriteCallsOncePerRunAndNamesTheUserBeingMined() throws Exception {
        McpToolDefinition archive = new McpToolDefinition("archive_document", "",
                "{\"type\":\"object\",\"properties\":{\"doc_id\":{\"type\":\"string\"}}}");
        inventory.set(Optional.of(ScanInventory.toolsOnly(List.of(LIST_DOCUMENTS, archive))));
        mining.preferences().setWriteTools(WriteToolOptIn.ALL);
        List<String> askedFor = new java.util.concurrent.CopyOnWriteArrayList<>();

        runToCompletion((user, calls) -> {
            askedFor.add(user);
            return false;
        });

        assertThat(askedFor).containsExactly("alice");
        assertThat(server.sent()).noneMatch(sent -> sent.call().operation().equals("tools/call archive_document"));
    }

    @Test
    void cannotMineWhileDisconnected() {
        inventory.set(Optional.empty());

        assertThat(mining.blocker()).contains(MiningBlocker.NOT_CONNECTED);
        assertThat(mining.start(MiningListener.NONE, WriteCallApproval.REFUSE)).isEmpty();
    }

    @Test
    void reportsEmptyUsersByName() throws Exception {
        ScriptedServer emptyForBob = new ScriptedServer().on((identity, call) -> Optional.of(MiningReply.of(200,
                structured(identity.name().equals("bob") ? "{}" : documentsFor(identity.name())))));
        AccessMining withEmptyBob = new AccessMining(new MiningInputs(inventory::get,
                new IdentityRosterSource(() -> new BearerTokenAuthStrategy("alice-token"), registry),
                () -> registry.primaryUser().id()), emptyForBob, new MiningPreferences(config), store, worker,
                () -> sendWorkers, McpEventLog.noop());
        CompletableFuture<MiningReport> finished = new CompletableFuture<>();

        withEmptyBob.start(listener(finished), WriteCallApproval.REFUSE);

        assertThat(finished.get(5, TimeUnit.SECONDS).warnings()).anyMatch(line -> line.startsWith("bob: "));
    }

    @Test
    void usesThePersistedPassCount() throws Exception {
        new MiningPreferences(config).setPasses(1);
        List<Integer> passes = new java.util.concurrent.CopyOnWriteArrayList<>();
        CompletableFuture<MiningReport> finished = new CompletableFuture<>();

        mining.start(new MiningListener() {
            public void progressed(String user, MiningStep step) { passes.add(step.pass()); }
            public void finished(MiningReport report) { finished.complete(report); }
        }, WriteCallApproval.REFUSE);

        finished.get(5, TimeUnit.SECONDS);
        assertThat(passes).containsOnly(1);
    }

    private AccessMining miningWith(ScriptedServer scripted) {
        return new AccessMining(new MiningInputs(inventory::get,
                new IdentityRosterSource(() -> new BearerTokenAuthStrategy("alice-token"), registry),
                () -> registry.primaryUser().id()), scripted, new MiningPreferences(config), store, worker,
                () -> sendWorkers, McpEventLog.noop());
    }

    private static MiningReport runToCompletion(AccessMining run) throws Exception {
        CompletableFuture<MiningReport> finished = new CompletableFuture<>();
        assertThat(run.start(listener(finished), WriteCallApproval.REFUSE)).isPresent();
        return finished.get(5, TimeUnit.SECONDS);
    }

    private MiningReport runToCompletion(WriteCallApproval approval) throws Exception {
        CompletableFuture<MiningReport> finished = new CompletableFuture<>();
        assertThat(mining.start(listener(finished), approval)).isPresent();
        return finished.get(5, TimeUnit.SECONDS);
    }

    private static MiningListener listener(CompletableFuture<MiningReport> finished) {
        return MiningListener.onFinished(finished::complete);
    }

    private static String documentsFor(String name) {
        String own = switch (name) {
            case "alice" -> "d-alice-0001";
            case "bob" -> "d-bob-0042";
            default -> null;
        };
        return own == null ? "{\"org_id\":\"org-1\"}"
                : "{\"org_id\":\"org-1\",\"documents\":[{\"doc_id\":\"" + own + "\"}]}";
    }

    private static void await(CountDownLatch latch) {
        try {
            latch.await(5, TimeUnit.SECONDS);
        } catch (InterruptedException interrupted) {
            Thread.currentThread().interrupt();
        }
    }
}
