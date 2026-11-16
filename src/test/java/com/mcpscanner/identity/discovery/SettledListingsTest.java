package com.mcpscanner.identity.discovery;

import com.mcpscanner.auth.BearerTokenAuthStrategy;
import com.mcpscanner.client.ConnectResult;
import com.mcpscanner.client.McpServerConfig;
import com.mcpscanner.client.PrimaryConnection;
import com.mcpscanner.client.TransportType;
import com.mcpscanner.identity.Identity;
import com.mcpscanner.identity.IdentityAuthKind;
import com.mcpscanner.identity.IdentityRegistry;
import com.mcpscanner.identity.IdentityRole;
import com.mcpscanner.identity.IdentityStore;
import com.mcpscanner.logging.McpEventLog;
import com.mcpscanner.testutil.InMemoryPersistedObject;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.time.Duration;
import java.util.List;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class SettledListingsTest {

    private static final ConnectResult EMPTY_CATALOG = new ConnectResult(List.of(), List.of(), List.of(), List.of(),
            null);

    private final IdentityRegistry registry = new IdentityRegistry(
            new IdentityStore(InMemoryPersistedObject.configStore(), McpEventLog.noop()));
    private final IdentityListings listings = new IdentityListings();
    private final CountDownLatch bobAnswers = new CountDownLatch(1);
    private final ExecutorService discoveryWorker = Executors.newSingleThreadExecutor();
    private final ExecutorService waiter = Executors.newSingleThreadExecutor();
    private Identity bob;

    @BeforeEach
    void comparesBob() {
        bob = registry.add(Identity.create("bob", IdentityRole.PEER, IdentityAuthKind.BEARER));
        registry.setCredential(bob.id(), new BearerTokenAuthStrategy("bob-token"));
        IdentityDiscoveryService discovery = new IdentityDiscoveryService(registry, this::discoverOnceBobAnswers,
                listings, discoveryWorker, McpEventLog.noop());
        discovery.start();
        discovery.onPrimaryConnected(new PrimaryConnection("http://target/mcp", TransportType.STREAMABLE_HTTP,
                EMPTY_CATALOG));
    }

    @AfterEach
    void stopWorkers() {
        bobAnswers.countDown();
        discoveryWorker.shutdownNow();
        waiter.shutdownNow();
    }

    @Test
    void waitsWhileAComparedUserIsStillBeingDiscovered() throws Exception {
        CompletableFuture<Void> settled = CompletableFuture.runAsync(
                new SettledListings(listings, Duration.ofSeconds(10))::await, waiter);

        assertThat(listings.outcome(bob.id())).contains(DiscoveryOutcome.Discovering.INSTANCE);
        assertThat(settled).isNotDone();
        bobAnswers.countDown();

        settled.get(10, TimeUnit.SECONDS);
        assertThat(listings.outcome(bob.id())).containsInstanceOf(DiscoveryOutcome.Listed.class);
    }

    @Test
    void failsLoudlyWhenDiscoveryDoesNotSettleInTime() {
        assertThatThrownBy(new SettledListings(listings, Duration.ofMillis(50))::await)
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("discovery");
    }

    private ConnectResult discoverOnceBobAnswers(McpServerConfig config) {
        try {
            bobAnswers.await();
        } catch (InterruptedException interrupted) {
            Thread.currentThread().interrupt();
        }
        return EMPTY_CATALOG;
    }
}
