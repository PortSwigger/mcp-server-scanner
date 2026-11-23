package com.mcpscanner;

import com.mcpscanner.testutil.InMemoryPreferences;
import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.Http;
import burp.api.montoya.http.RequestOptions;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.persistence.PersistedObject;
import com.mcpscanner.auth.BearerTokenAuthStrategy;
import com.mcpscanner.client.McpServerConfig;
import com.mcpscanner.client.TransportType;
import com.mcpscanner.identity.Identity;
import com.mcpscanner.identity.IdentityAuthKind;
import com.mcpscanner.identity.IdentityRole;
import com.mcpscanner.identity.credentials.ScopeApprovals;
import com.mcpscanner.identity.discovery.DiscoveryOutcome;
import com.mcpscanner.testutil.MontoyaTestFactory;
import com.mcpscanner.testutil.ScriptedBurpHttp;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;

import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.awaitility.Awaitility.await;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.argThat;
import static org.mockito.Mockito.RETURNS_DEEP_STUBS;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

class IdentityWiringTest {

    private static final String ENDPOINT = "https://mcp.example.test/mcp";

    private final MontoyaApi api = mock(MontoyaApi.class, RETURNS_DEEP_STUBS);
    private final Http http = mock(Http.class);
    private final PersistedObject savedSettings = mock(PersistedObject.class);
    private final ScriptedBurpHttp fakeServer = ScriptedBurpHttp.fakeMcpServer();
    private final ShutdownHooks shutdown = new ShutdownHooks(failure -> {
        throw new AssertionError(failure);
    });
    private ExtensionFoundation foundation;
    private ConnectionWiring connection;
    private IdentityWiring identities;
    private IdentityDiscoveryWiring discovery;

    @BeforeEach
    void setUp() {
        MontoyaTestFactory.install();
        when(api.http()).thenReturn(http);
        when(api.persistence().extensionData()).thenReturn(savedSettings);
        when(api.persistence().preferences()).thenReturn(new InMemoryPreferences());
        when(savedSettings.getBoolean("mcp.networking.use_burp")).thenReturn(null);
        when(http.sendRequest(any(HttpRequest.class), any(RequestOptions.class)))
                .thenAnswer(invocation -> fakeServer.sendRequest(invocation.getArgument(0, HttpRequest.class),
                        invocation.getArgument(1, RequestOptions.class)));
        foundation = ExtensionFoundation.create(api);
        connection = ConnectionWiring.create(api, foundation);
        identities = IdentityWiring.create(foundation, OAuthWiring.create(api, foundation, connection.burpHttp()));
        discovery = IdentityDiscoveryWiring.create(foundation, connection);
        connection.start(shutdown);
        discovery.addShutdownHooks(shutdown);
        identities.addShutdownHooks(shutdown);
    }

    @AfterEach
    void unload() {
        shutdown.extensionUnloaded();
    }

    @ParameterizedTest
    @EnumSource(value = TransportType.class, names = {"MODERN_HTTP", "STREAMABLE_HTTP"})
    void comparedIdentitiesDiscoverThroughBurpAfterThePrimaryConnects(TransportType transport) {
        Identity bob = foundation.identities().add(Identity.create("bob", IdentityRole.PEER, IdentityAuthKind.BEARER));
        foundation.identities().setCredential(bob.id(), new BearerTokenAuthStrategy("bob"));

        connection.clientManager().connect(new McpServerConfig(ENDPOINT, transport,
                new BearerTokenAuthStrategy("alice")));

        await().until(() -> discovery.listings().outcome(bob.id())
                .filter(DiscoveryOutcome.Listed.class::isInstance).isPresent());
        verify(http).sendRequest(argThat(request -> request.bodyToString().contains("tools/list")
                && "Bearer bob".equals(request.headerValue("Authorization"))), any(RequestOptions.class));
        assertThat(connection.scannerSession().scannerHeaders()).containsEntry("Authorization", "Bearer alice");
    }

    @ParameterizedTest
    @EnumSource(value = TransportType.class, names = {"MODERN_HTTP"})
    void disconnectingThePrimaryClearsTheListings(TransportType transport) {
        connection.clientManager().connect(new McpServerConfig(ENDPOINT, transport,
                new BearerTokenAuthStrategy("alice")));
        assertThat(discovery.listings().outcomes()).isNotEmpty();

        connection.clientManager().disconnect();

        assertThat(discovery.listings().outcomes()).isEmpty();
    }

    @Test
    void identityCredentialsSurviveADisconnectSoConnectingAsAnotherUserUsesThem() {
        AccessWiring access = AccessWiring.create(foundation, connection, discovery.listings());
        RequestBuildingWiring requests = RequestBuildingWiring.create(foundation, connection, access.authHolder());
        connection.resetOnDisconnect(requests.sessionResets());
        connection.resetOnDisconnect(ScanningWiring.create(api, foundation, connection, requests, access,
                ScanFoundation.create(api, foundation, connection),
                com.mcpscanner.checks.registry.CheckInstrumentation.NONE, java.util.function.UnaryOperator.identity(),
                com.mcpscanner.checks.api.SignedInConsent.OPTED_OUT)
                .sessionResets());
        connection.resetOnDisconnect(access.sessionResets());
        BearerTokenAuthStrategy bobToken = new BearerTokenAuthStrategy("bob");
        connection.clientManager().connect(new McpServerConfig(ENDPOINT, TransportType.MODERN_HTTP,
                new BearerTokenAuthStrategy("alice")));
        Identity bob = bobWith(bobToken);
        connection.clientManager().disconnect();

        foundation.identities().makePrimary(bob.id());

        assertThat(identities.credentialServices(Optional::empty, ScopeApprovals.promptRequired()).primaryCredentials()
                .connectionCredential()).isSameAs(bobToken);
    }

    @Test
    void editingTheStoredEndpointKeepsIdentityCredentialsUntilTheTabCommitsANewOrigin() {
        Identity bob = bobWith(new BearerTokenAuthStrategy("bob"));

        foundation.configStore().setEndpoint("");
        foundation.configStore().setEndpoint("https://other.example.test/mcp");

        assertThat(foundation.identities().credential(bob.id())).isPresent();
    }

    @Test
    void unloadingForgetsIdentityCredentials() {
        Identity bob = bobWith(new BearerTokenAuthStrategy("bob"));

        shutdown.extensionUnloaded();

        assertThat(foundation.identities().credential(bob.id())).isEmpty();
    }

    private Identity bobWith(BearerTokenAuthStrategy credential) {
        Identity bob = foundation.identities().add(Identity.create("bob", IdentityRole.PEER, IdentityAuthKind.BEARER));
        foundation.identities().setCredential(bob.id(), credential);
        return bob;
    }
}
