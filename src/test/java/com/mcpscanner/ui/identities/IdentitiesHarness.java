package com.mcpscanner.ui.identities;

import com.mcpscanner.auth.AuthStrategy;
import com.mcpscanner.auth.BearerTokenAuthStrategy;
import com.mcpscanner.auth.oauth.OAuthClientHints;
import com.mcpscanner.config.ExtensionConfigStore;
import com.mcpscanner.identity.ConnectedIdentity;
import com.mcpscanner.identity.ConnectionFreshness;
import com.mcpscanner.identity.Identity;
import com.mcpscanner.identity.IdentityAuthKind;
import com.mcpscanner.identity.IdentityRegistry;
import com.mcpscanner.identity.IdentityRole;
import com.mcpscanner.identity.IdentityStore;
import com.mcpscanner.identity.ToolCallRefusals;
import com.mcpscanner.identity.credentials.IdentityCredentialServices;
import com.mcpscanner.client.ConnectResult;
import com.mcpscanner.client.McpServerConfig;
import com.mcpscanner.client.PrimaryConnection;
import com.mcpscanner.client.TransportType;
import com.mcpscanner.identity.discovery.IdentityDiscoveryService;
import com.mcpscanner.identity.discovery.IdentityListings;
import com.mcpscanner.mcp.McpToolDefinition;
import com.mcpscanner.mcp.ServerMetadata;
import com.mcpscanner.logging.McpEventLog;
import com.mcpscanner.testutil.InMemoryPersistedObject;

import javax.swing.SwingUtilities;
import java.awt.Component;
import java.net.URI;
import java.time.Duration;
import java.util.List;
import java.util.Optional;
import java.util.Queue;
import java.util.concurrent.ConcurrentLinkedQueue;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.Executors;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;

final class IdentitiesHarness implements AutoCloseable {

    static final OAuthClientHints OAUTH = new OAuthClientHints(URI.create("https://auth.example.com"),
            List.of("read"), "client", null, false, 0, Duration.ofSeconds(30));

    final ExtensionConfigStore config = InMemoryPersistedObject.configStore();
    final IdentityRegistry registry = new IdentityRegistry(new IdentityStore(config, McpEventLog.noop()));
    final IdentityListings listings = new IdentityListings();
    final ToolCallRefusals refusals = new ToolCallRefusals(registry);
    final AtomicReference<Optional<OAuthClientHints>> sharedClient = new AtomicReference<>(Optional.of(OAUTH));
    final AtomicBoolean connected = new AtomicBoolean();
    final AtomicBoolean connecting = new AtomicBoolean();
    final AtomicReference<Optional<ConnectedIdentity>> connectedAs = new AtomicReference<>(Optional.empty());
    final AtomicInteger reconnects = new AtomicInteger();
    final List<String> connectAsWhenReconnectStarted = new CopyOnWriteArrayList<>();
    final AtomicBoolean confirmReconnect = new AtomicBoolean(true);
    final List<String> reconnectPrompts = new CopyOnWriteArrayList<>();
    final CountDownLatch signInGate = new CountDownLatch(1);
    final AtomicBoolean holdSignIns = new AtomicBoolean();
    final Queue<Runnable> pendingDiscoveries = new ConcurrentLinkedQueue<>();
    final List<String> discoveredWith = new CopyOnWriteArrayList<>();
    final IdentityDiscoveryService discovery = new IdentityDiscoveryService(registry, this::discoverAs, listings,
            pendingDiscoveries::add, McpEventLog.noop());
    final IdentityCredentialServices credentials;
    final IdentityUiServices services;

    IdentitiesHarness() {
        credentials = IdentityCredentialServices.create(registry, sharedClient::get, this::signIn,
                Executors.newSingleThreadExecutor(), McpEventLog.noop());
        discovery.start();
        services = new IdentityUiServices(registry, credentials, listings, discovery, refusals,
                IdentityConnection.of(connected::get, connecting::get, this::reconnectAs, connectedAs::get), this::confirmReconnect);
    }

    Identity add(String name, IdentityRole role, IdentityAuthKind kind) {
        return registry.add(Identity.create(name, role, kind));
    }

    void connectedAs(Identity user, AuthStrategy connectionAuth) {
        connected.set(true);
        connectedAs.set(Optional.of(new ConnectionFreshness(registry).snapshot(user.id(), connectionAuth)));
    }

    void connectDiscovery() {
        connected.set(true);
        discovery.onPrimaryConnected(new PrimaryConnection("http://target/mcp", TransportType.STREAMABLE_HTTP,
                catalog("search")));
    }

    void runDiscoveries() {
        for (Runnable next = pendingDiscoveries.poll(); next != null; next = pendingDiscoveries.poll()) {
            next.run();
        }
    }

    Identity userOne() {
        return registry.primaryUser();
    }

    Identity identity(String id) {
        return registry.find(id).orElseThrow();
    }

    Identity named(String name) {
        return registry.identities().stream().filter(identity -> identity.name().equals(name)).findFirst()
                .orElseThrow(() -> new AssertionError("No identity named " + name));
    }

    private void reconnectAs(Runnable switchUser) {
        connectAsWhenReconnectStarted.add(registry.primaryUser().name());
        switchUser.run();
        reconnects.incrementAndGet();
    }

    private boolean confirmReconnect(Component parent, String user, String previous) {
        reconnectPrompts.add(previous + " -> " + user);
        return confirmReconnect.get();
    }

    private ConnectResult discoverAs(McpServerConfig config) {
        discoveredWith.add(config.auth().headers().get("Authorization"));
        return catalog("search", "delete_project");
    }

    private static ConnectResult catalog(String... tools) {
        return new ConnectResult(java.util.Arrays.stream(tools).map(name -> new McpToolDefinition(name, "", "{}"))
                .toList(), List.of(), List.of(), List.of(), ServerMetadata.empty());
    }

    private AuthStrategy signIn(Identity identity, OAuthClientHints hints) {
        if (holdSignIns.get()) {
            try {
                signInGate.await();
            } catch (InterruptedException interrupted) {
                Thread.currentThread().interrupt();
                throw new IllegalStateException(interrupted);
            }
        }
        return new BearerTokenAuthStrategy("signed-in-" + identity.name());
    }

    @Override
    public void close() {
        signInGate.countDown();
        credentials.close();
    }

    static void onEdt(Runnable runnable) throws Exception {
        if (SwingUtilities.isEventDispatchThread()) {
            runnable.run();
        } else {
            SwingUtilities.invokeAndWait(runnable);
        }
    }

    static <T> T fromEdt(java.util.function.Supplier<T> supplier) throws Exception {
        AtomicReference<T> result = new AtomicReference<>();
        onEdt(() -> result.set(supplier.get()));
        return result.get();
    }
}
