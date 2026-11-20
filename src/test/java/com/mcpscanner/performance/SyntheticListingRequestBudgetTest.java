package com.mcpscanner.performance;

import com.mcpscanner.auth.BearerTokenAuthStrategy;
import com.mcpscanner.checks.api.crossidentity.SyntheticPrincipals;
import com.mcpscanner.client.ConnectResult;
import com.mcpscanner.client.IsolatedCatalogDiscovery;
import com.mcpscanner.client.JdkProtocolHttpTransport;
import com.mcpscanner.client.McpFixtureProfile;
import com.mcpscanner.client.McpFixtureServer;
import com.mcpscanner.client.McpHttpClients;
import com.mcpscanner.client.PrimaryConnection;
import com.mcpscanner.client.ScannerSessionSettings;
import com.mcpscanner.client.TransportType;
import com.mcpscanner.config.ClientIdentityProvider;
import com.mcpscanner.identity.IdentityRegistry;
import com.mcpscanner.identity.IdentityStore;
import com.mcpscanner.identity.discovery.IdentityDiscoveryService;
import com.mcpscanner.identity.discovery.IdentityListings;
import com.mcpscanner.logging.McpEventLog;
import com.mcpscanner.testutil.InMemoryPersistedObject;
import com.mcpscanner.testutil.MontoyaTestFactory;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.List;

class SyntheticListingRequestBudgetTest {

    private static final String[] LEGACY_VERSIONS = {"2025-11-25", "2025-06-18", "2025-03-26"};
    private static final BearerTokenAuthStrategy PRIMARY_AUTH = new BearerTokenAuthStrategy("alice");

    @BeforeEach
    void installMontoya() {
        MontoyaTestFactory.install();
    }

    @Test
    void eachCheckAccessRunListsOnceWithNoCredentialAndOnceWithAFakeToken() throws Exception {
        try (McpFixtureServer server = new McpFixtureServer(McpFixtureProfile.streamable(LEGACY_VERSIONS))) {
            IdentityDiscoveryService discovery = discoveryService();
            discovery.onPrimaryConnected(new PrimaryConnection(server.endpoint(), TransportType.STREAMABLE_HTTP,
                    new ConnectResult(List.of(), List.of(), List.of(), List.of(), null)));
            server.forgetRequests();

            discovery.withSyntheticListings().discoverMissing();

            RequestBudgets.assertWithin("Check access run, synthetic listings, initialize-based HTTP",
                    server.requests());
        }
    }

    private static IdentityDiscoveryService discoveryService() {
        IsolatedCatalogDiscovery isolated = new IsolatedCatalogDiscovery(McpEventLog.noop(),
                ClientIdentityProvider.defaults(), new JdkProtocolHttpTransport(McpHttpClients.upstream()),
                ScannerSessionSettings.defaults());
        IdentityDiscoveryService discovery = new IdentityDiscoveryService(new IdentityRegistry(
                new IdentityStore(InMemoryPersistedObject.configStore(), McpEventLog.noop())),
                isolated::discoverRecorded, new IdentityListings(), Runnable::run, McpEventLog.noop(),
                new SyntheticPrincipals(() -> PRIMARY_AUTH));
        discovery.start();
        return discovery;
    }
}
