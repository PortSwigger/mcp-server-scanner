package com.mcpscanner.integration;

import com.mcpscanner.access.IdentityRequests;
import com.mcpscanner.access.mining.AccessMining;
import com.mcpscanner.access.mining.MiningInputs;
import com.mcpscanner.access.mining.MiningListener;
import com.mcpscanner.access.mining.MiningPreferences;
import com.mcpscanner.access.mining.MiningReport;
import com.mcpscanner.access.mining.RoutedMiningSender;
import com.mcpscanner.access.mining.WriteCallApproval;
import com.mcpscanner.auth.BearerTokenAuthStrategy;
import com.mcpscanner.client.ConnectResult;
import com.mcpscanner.client.McpDiscoveryClient;
import com.mcpscanner.client.TransportType;
import com.mcpscanner.config.ExtensionConfigStore;
import com.mcpscanner.config.ResourceCap;
import com.mcpscanner.cvetargets.requests.VerbatimHeaderHttp;
import com.mcpscanner.identity.Identity;
import com.mcpscanner.identity.IdentityAuthKind;
import com.mcpscanner.identity.IdentityRegistry;
import com.mcpscanner.identity.IdentityRole;
import com.mcpscanner.identity.IdentityRosterSource;
import com.mcpscanner.identity.IdentityStore;
import com.mcpscanner.identity.MinedValue;
import com.mcpscanner.identity.RegistryOwnedValues;
import com.mcpscanner.logging.McpEventLog;
import com.mcpscanner.scan.McpRepeaterRequestFactory;
import com.mcpscanner.scan.ScanInventory;
import com.mcpscanner.testutil.InMemoryPersistedObject;

import java.time.Duration;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;

import static org.mockito.Mockito.mock;

final class CollectIdsFixture implements AutoCloseable {

    private static final Duration COLLECTING_TIMEOUT = Duration.ofMinutes(3);

    private final ExecutorService worker = Executors.newSingleThreadExecutor();
    private final ExecutorService sendWorkers = Executors.newFixedThreadPool(
            (int) ResourceCap.EXTENSION_SCAN_WORKERS.defaultValue());
    private final IdentityRegistry registry;
    private final RegistryOwnedValues store;
    private final Identity alice;
    private final Identity bob;
    private final ScannerProxyFixture proxy;
    private final AccessMining mining;

    private CollectIdsFixture(String endpoint) throws Exception {
        ExtensionConfigStore config = InMemoryPersistedObject.configStore();
        registry = new IdentityRegistry(new IdentityStore(config, mock(McpEventLog.class)));
        alice = registry.primaryUser().withName("alice");
        registry.update(alice);
        bob = registry.add(Identity.create("bob", IdentityRole.PEER, IdentityAuthKind.BEARER).withCompared(true));
        registry.setCredential(bob.id(), new BearerTokenAuthStrategy("bob-token"));
        store = new RegistryOwnedValues(registry);
        proxy = ScannerProxyFixture.connect(endpoint, TransportType.STREAMABLE_HTTP);
        IdentityRosterSource roster = new IdentityRosterSource(() -> new BearerTokenAuthStrategy("alice-token"),
                registry);
        McpRepeaterRequestFactory primary = ProxiedPrimaryRequests.of(proxy,
                Map.of("Authorization", "Bearer alice-token"));
        ScanInventory inventory = inventory(new McpDiscoveryClient(proxy.session()).discoverCatalog());
        mining = new AccessMining(new MiningInputs(() -> Optional.of(inventory), roster,
                () -> registry.primaryUser().id()),
                new RoutedMiningSender(call -> primary.requestFor(call.message()), new IdentityRequests(roster),
                        proxy.routed(new VerbatimHeaderHttp())),
                new MiningPreferences(config), store, worker, () -> sendWorkers, McpEventLog.noop());
    }

    static CollectIdsFixture connect(String endpoint) throws Exception {
        return new CollectIdsFixture(endpoint);
    }

    MiningReport collect() throws Exception {
        CompletableFuture<MiningReport> finished = new CompletableFuture<>();
        mining.start(MiningListener.onFinished(finished::complete), WriteCallApproval.REFUSE).orElseThrow();
        return finished.get(COLLECTING_TIMEOUT.toSeconds(), TimeUnit.SECONDS);
    }

    AccessMining mining() {
        return mining;
    }

    List<MinedValue> aliceValues() {
        return store.valuesOf(alice.id()).mined();
    }

    List<MinedValue> bobValues() {
        return store.valuesOf(bob.id()).mined();
    }

    @Override
    public void close() throws Exception {
        worker.shutdownNow();
        sendWorkers.shutdownNow();
        proxy.close();
    }

    private static ScanInventory inventory(ConnectResult catalog) {
        return new ScanInventory(catalog.tools(), catalog.resources(), catalog.resourceTemplates(), catalog.prompts());
    }
}
