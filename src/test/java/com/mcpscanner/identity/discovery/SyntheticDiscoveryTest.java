package com.mcpscanner.identity.discovery;

import burp.api.montoya.http.message.HttpRequestResponse;
import com.mcpscanner.auth.AuthStrategy;
import com.mcpscanner.auth.BearerTokenAuthStrategy;
import com.mcpscanner.checks.api.AccessItemKey;
import com.mcpscanner.checks.api.Principal;
import com.mcpscanner.checks.api.crossidentity.SyntheticPrincipals;
import com.mcpscanner.client.ConnectResult;
import com.mcpscanner.client.McpServerConfig;
import com.mcpscanner.client.PrimaryConnection;
import com.mcpscanner.client.RecordedCatalog;
import com.mcpscanner.client.TransportType;
import com.mcpscanner.identity.Identity;
import com.mcpscanner.identity.IdentityAuthKind;
import com.mcpscanner.identity.IdentityRegistry;
import com.mcpscanner.identity.IdentityRole;
import com.mcpscanner.identity.IdentityStore;
import com.mcpscanner.logging.McpEventLog;
import com.mcpscanner.testutil.InMemoryPersistedObject;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.ArrayList;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;

class SyntheticDiscoveryTest {

    private static final String ENDPOINT = "http://127.0.0.1:9/mcp";
    private static final AccessItemKey LIST_USERS = new AccessItemKey(AccessItemKey.Kind.TOOL, "list_users");
    private static final AuthStrategy PRIMARY_AUTH = new BearerTokenAuthStrategy("alice");

    private final List<McpServerConfig> discovered = new ArrayList<>();
    private final IdentityListings listings = new IdentityListings();
    private final HttpRequestResponse exchange = mock(HttpRequestResponse.class);
    private IdentityRegistry registry;
    private final HttpRequestResponse primaryExchange = mock(HttpRequestResponse.class);
    private final SyntheticPrincipals synthetic = new SyntheticPrincipals(() -> PRIMARY_AUTH);
    private IdentityDiscoveryService service;
    private PreComparisonDiscovery checkAccess;

    @BeforeEach
    void setUp() {
        registry = new IdentityRegistry(new IdentityStore(InMemoryPersistedObject.configStore(), McpEventLog.noop()));
        service = new IdentityDiscoveryService(registry, this::discover, listings, Runnable::run, McpEventLog.noop(),
                synthetic);
        service.start();
        service.onPrimaryConnected(new PrimaryConnection(ENDPOINT, TransportType.SSE, catalog("search"),
                List.of(primaryExchange)));
        checkAccess = service.withSyntheticListings();
    }

    @Test
    void aScansDiscoveryNeverListsAsTheSyntheticPrincipals() {
        service.discoverMissing();

        assertThat(discovered).isEmpty();
        assertThat(listings.outcome(Principal.FAKE_TOKEN_ID)).isEmpty();
        assertThat(listings.outcome(Principal.ANONYMOUS_ID)).isEmpty();
    }

    @Test
    void aScanStartedDuringCheckAccessKeepsTheRunsSyntheticListings() {
        checkAccess.discoverMissing();

        service.discoverMissing();

        assertThat(discovered).hasSize(2);
        assertThat(listings.lists(Principal.FAKE_TOKEN_ID, LIST_USERS)).contains(true);
        assertThat(listings.lists(Principal.ANONYMOUS_ID, LIST_USERS)).contains(false);
    }

    @Test
    void listsAsNoCredentialAndFakeTokenBeforeComparingEvenWithoutComparedUsers() {
        checkAccess.discoverMissing();

        assertThat(discovered).extracting(config -> config.auth().headers()).hasSize(2);
        assertThat(discovered.get(0).auth().headers()).isEmpty();
        assertThat(discovered.get(1).auth().headers().get("Authorization")).startsWith("Bearer invalid_");
        assertThat(listings.lists(Principal.ANONYMOUS_ID, LIST_USERS)).contains(false);
        assertThat(listings.lists(Principal.FAKE_TOKEN_ID, LIST_USERS)).contains(true);
    }

    @Test
    void eachRunListsWithANewFakeToken() {
        checkAccess.discoverMissing();
        checkAccess.discoverMissing();

        assertThat(discovered).extracting(config -> config.auth().headers().get("Authorization"))
                .filteredOn(value -> value != null).doesNotHaveDuplicates().hasSize(2);
    }

    @Test
    void theRunsCallsUseTheFakeTokenItsListingWasSentWith() {
        checkAccess.discoverMissing();

        assertThat(synthetic.fakeToken().credentialHeaders().get().get("Authorization"))
                .isEqualTo(discovered.get(1).auth().headers().get("Authorization"));
    }

    @Test
    void keepsEachSyntheticToolsListExchangeAsEvidence() {
        checkAccess.discoverMissing();

        assertThat(listings.toolsListExchanges(Principal.FAKE_TOKEN_ID)).singleElement().isSameAs(exchange);
        assertThat(listings.toolsListExchanges(Principal.ANONYMOUS_ID)).singleElement().isSameAs(exchange);
    }

    @Test
    void thePrimarysEvidenceIsTheToolsListRecordedWhenItConnectedAndNothingIsSent() {
        assertThat(service.toolsListExchanges(Principal.PRIMARY_ID)).singleElement().isSameAs(primaryExchange);
        assertThat(discovered).isEmpty();
        assertThat(listings.lists(Principal.PRIMARY_ID, new AccessItemKey(AccessItemKey.Kind.TOOL, "search")))
                .contains(true);
    }

    @Test
    void registryChangesKeepTheSyntheticListings() {
        checkAccess.discoverMissing();

        registry.add(Identity.create("bob", IdentityRole.PEER, IdentityAuthKind.BEARER));

        assertThat(listings.outcome(Principal.FAKE_TOKEN_ID)).isPresent();
        assertThat(listings.outcome(Principal.ANONYMOUS_ID)).isPresent();
    }

    @Test
    void theFakeTokenIsNeverSavedAsAUserOrCredential() {
        int users = registry.identities().size();

        checkAccess.discoverMissing();

        assertThat(registry.identities()).hasSize(users);
        assertThat(registry.identities()).allSatisfy(identity -> assertThat(registry.credential(identity.id())
                .map(AuthStrategy::headers).map(Object::toString).orElse("")).doesNotContain("invalid_"));
    }

    private RecordedCatalog discover(McpServerConfig config) {
        discovered.add(config);
        String authorization = config.auth().headers().getOrDefault("Authorization", "");
        ConnectResult catalog = authorization.startsWith("Bearer invalid_") ? catalog("search", "list_users")
                : authorization.isEmpty() ? catalog() : catalog("search");
        return new RecordedCatalog(catalog, List.of(exchange));
    }

    private static ConnectResult catalog(String... tools) {
        return IdentityDiscoveryServiceTest.catalog(tools);
    }
}
