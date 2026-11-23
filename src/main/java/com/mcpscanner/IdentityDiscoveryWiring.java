package com.mcpscanner;

import com.mcpscanner.auth.CurrentAuthHolder;
import com.mcpscanner.checks.api.crossidentity.SyntheticPrincipals;
import com.mcpscanner.client.McpClientManager;
import com.mcpscanner.identity.discovery.IdentityDiscoveryService;
import com.mcpscanner.identity.discovery.IdentityListings;

import java.util.concurrent.ExecutorService;

final class IdentityDiscoveryWiring {

    private final IdentityListings listings;
    private final IdentityDiscoveryService discovery;
    private final ExecutorService worker;
    private final SyntheticPrincipals synthetic;

    private IdentityDiscoveryWiring(IdentityListings listings, IdentityDiscoveryService discovery,
                                    ExecutorService worker, SyntheticPrincipals synthetic) {
        this.synthetic = synthetic;
        this.listings = listings;
        this.discovery = discovery;
        this.worker = worker;
    }

    static IdentityDiscoveryWiring create(ExtensionFoundation foundation, ConnectionWiring connection) {
        return create(foundation, connection, new CurrentAuthHolder());
    }

    static IdentityDiscoveryWiring create(ExtensionFoundation foundation, ConnectionWiring connection,
                                          CurrentAuthHolder primaryAuth) {
        IdentityListings listings = new IdentityListings();
        ExecutorService worker = DaemonWorkers.single("mcp-identity-discovery");
        SyntheticPrincipals synthetic = new SyntheticPrincipals(primaryAuth);
        IdentityDiscoveryService discovery = new IdentityDiscoveryService(foundation.identities(),
                connection.newIsolatedDiscovery()::discoverRecorded, listings, worker, foundation.eventLog(), synthetic);
        discovery.start();
        McpClientManager clientManager = connection.clientManager();
        clientManager.addConnectListener(discovery::onPrimaryConnected);
        clientManager.addDisconnectListener(discovery::onDisconnected);
        return new IdentityDiscoveryWiring(listings, discovery, worker, synthetic);
    }

    SyntheticPrincipals synthetic() {
        return synthetic;
    }

    IdentityListings listings() {
        return listings;
    }

    IdentityDiscoveryService discovery() {
        return discovery;
    }

    void addShutdownHooks(ShutdownHooks shutdown) {
        shutdown.add("Identity discovery", worker::shutdownNow);
    }
}
