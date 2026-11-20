package com.mcpscanner.automation;

import burp.api.montoya.http.sessions.CookieJar;
import com.mcpscanner.access.WriteReplayConfirmations;
import com.mcpscanner.auth.CurrentAuthHolder;
import com.mcpscanner.auth.oauth.OAuthSignIn;
import com.mcpscanner.auth.oauth.SignInListener;
import com.mcpscanner.client.ConnectResult;
import com.mcpscanner.client.McpClientManager;
import com.mcpscanner.client.McpServerConfig;
import com.mcpscanner.client.TransportType;
import com.mcpscanner.identity.Identity;
import com.mcpscanner.identity.IdentityRegistry;
import com.mcpscanner.identity.IdentityStore;
import com.mcpscanner.logging.McpEventLog;
import com.mcpscanner.mcp.McpToolDefinition;
import com.mcpscanner.testutil.InMemoryPersistedObject;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;

import java.net.URI;
import java.time.Clock;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.Map;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

class HeadlessConnectionTest {

    private static final String ENDPOINT = "http://target/mcp";
    private static final McpToolDefinition SEARCH = new McpToolDefinition("search", "", "{}");

    private final McpClientManager clientManager = mock(McpClientManager.class);
    private final CurrentAuthHolder authHolder = new CurrentAuthHolder();
    private final List<Boolean> networking = new ArrayList<>();
    private final IdentityRegistry registry = new IdentityRegistry(
            new IdentityStore(InMemoryPersistedObject.configStore(), McpEventLog.noop()));
    private final WriteReplayConfirmations confirmations = new WriteReplayConfirmations();
    private final CookieJar jar = mock(CookieJar.class);
    private final List<Boolean> optIns = new ArrayList<>();
    private final SignInListener signIns = mock(SignInListener.class);
    private final HeadlessConnection connection = new HeadlessConnection(clientManager, networking::add,
            new IdentityHandover(registry, confirmations, (item, expectation) -> { }, seeds -> { }), authHolder,
            new SignedInSessionSeed(() -> jar, optIns::add, signIns, Clock.systemUTC()));

    @BeforeEach
    void connectsToAServerListingOneTool() {
        when(clientManager.connect(any())).thenAnswer(connecting -> {
            authHolder.clear();
            confirmations.clear();
            return new ConnectResult(List.of(SEARCH), List.of(), List.of(), List.of(), null);
        });
    }

    @Test
    void launchesTakeTheConnectionOneAtATime() throws Exception {
        CountDownLatch firstHolding = new CountDownLatch(1);
        CountDownLatch releaseFirst = new CountDownLatch(1);
        List<String> order = new CopyOnWriteArrayList<>();
        ExecutorService launchers = Executors.newFixedThreadPool(2);
        try {
            Future<String> first = launchers.submit(() -> connection.exclusively(() -> {
                firstHolding.countDown();
                awaitQuietly(releaseFirst);
                order.add("first");
                return "first";
            }));
            assertThat(firstHolding.await(5, TimeUnit.SECONDS)).isTrue();
            Future<String> second = launchers.submit(() -> connection.exclusively(() -> {
                order.add("second");
                return "second";
            }));
            assertThat(order).isEmpty();
            releaseFirst.countDown();

            assertThat(List.of(first.get(5, TimeUnit.SECONDS), second.get(5, TimeUnit.SECONDS)))
                    .containsExactly("first", "second");
            assertThat(order).containsExactly("first", "second");
        } finally {
            launchers.shutdownNow();
        }
    }

    private static void awaitQuietly(CountDownLatch latch) {
        try {
            latch.await(5, TimeUnit.SECONDS);
        } catch (InterruptedException interrupted) {
            Thread.currentThread().interrupt();
        }
    }

    @Test
    void beginsAConnectAttemptBeforeConnecting() {
        connection.connect(command(null, CommandIdentities.NONE));

        org.mockito.InOrder order = org.mockito.Mockito.inOrder(clientManager);
        order.verify(clientManager).beginConnectAttempt();
        order.verify(clientManager).connect(any());
    }

    @Test
    void changesBurpNetworkingOnlyWhenTheCommandSaysSo() {
        connection.connect(command(null, CommandIdentities.NONE));
        connection.connect(command(false, CommandIdentities.NONE));

        assertThat(networking).containsExactly(false);
    }

    @Test
    void connectsWithTheCommandsEndpointTransportAndCredential() {
        connection.connect(command(null, CommandIdentities.NONE));

        ArgumentCaptor<McpServerConfig> config = ArgumentCaptor.forClass(McpServerConfig.class);
        verify(clientManager).connect(config.capture());
        assertThat(config.getValue().endpoint()).isEqualTo(ENDPOINT);
        assertThat(config.getValue().transport()).isEqualTo(TransportType.STREAMABLE_HTTP);
        assertThat(config.getValue().auth().headers()).containsEntry("Authorization", "Bearer alice-token");
    }

    @Test
    void theConnectionsCredentialOutlivesTheResetThatConnectingApplies() {
        HeadlessConnected connected = connection.connect(command(null, CommandIdentities.NONE));

        assertThat(authHolder.get()).isSameAs(connected.strategy());
        assertThat(connected.inventory().tools()).containsExactly(SEARCH);
    }

    @Test
    void handsTheUsersOverBeforeConnectingAndConfirmsTheirWritesAfterwards() {
        CommandIdentities identities = new CommandIdentities(new CommandUser("alice", null, null, null, Map.of()),
                List.of(new CommandUser("bob", null, new CommandAuth("bob-token", Map.of()), null, Map.of())),
                Set.of("search"), List.of(), List.of());

        connection.connect(command(null, identities));

        assertThat(registry.primaryUser().name()).isEqualTo("alice");
        assertThat(registry.compared()).extracting(Identity::name).containsExactly("bob");
        assertThat(confirmations.confirmed("search")).isTrue();
    }

    @Test
    void theConnectAsUserAndTheConnectionShareOneHandedOverOAuthSession() {
        CommandIdentities identities = new CommandIdentities(new CommandUser("alice", null, null, null, Map.of()),
                List.of(), Set.of(), List.of(), List.of());

        HeadlessConnected connected = connection.connect(new CheckAccessCommand(ENDPOINT,
                TransportType.STREAMABLE_HTTP, CommandAuth.handedOver(HandedOverOAuthStrategyTest.SESSION), null,
                identities));

        assertThat(registry.credential(registry.primaryUser().id())).containsSame(connected.strategy());
        assertThat(authHolder.get().refreshGrantStore()).isPresent();
    }

    @Test
    void seedsTheSignedInSessionAfterBeginningTheAttemptAndBeforeConnecting() {
        connection.connect(signedInScan());

        org.mockito.InOrder order = org.mockito.Mockito.inOrder(clientManager, jar, signIns);
        order.verify(clientManager).beginConnectAttempt();
        order.verify(jar).setCookie(org.mockito.ArgumentMatchers.eq("sid"), org.mockito.ArgumentMatchers.eq("abc"),
                org.mockito.ArgumentMatchers.eq("/"), org.mockito.ArgumentMatchers.eq("target"), any());
        order.verify(signIns).signedIn(any());
        order.verify(clientManager).connect(any());
        assertThat(optIns).containsExactly(true);
    }

    @Test
    void theScannerClientSignsInForTheEndpointBeingConnected() {
        connection.connect(signedInScan());

        ArgumentCaptor<OAuthSignIn> signIn = ArgumentCaptor.forClass(OAuthSignIn.class);
        verify(signIns).signedIn(signIn.capture());
        assertThat(signIn.getValue().resource()).isEqualTo(URI.create(ENDPOINT));
        assertThat(signIn.getValue().clientName()).contains("MCP Server Scanner");
    }

    @Test
    void seedsNothingWithoutASignedInSession() {
        connection.connect(command(null, CommandIdentities.NONE));
        connection.connect(new ScanAllCommand(ENDPOINT, null, null, null, null, null, false, null));

        verifyNoInteractions(jar, signIns);
        assertThat(optIns).isEmpty();
    }

    private static ScanAllCommand signedInScan() {
        CommandScannerClient client = new CommandScannerClient(URI.create("http://target"),
                URI.create("http://target/authorize"), null, "client-1", "MCP Server Scanner",
                URI.create("http://127.0.0.1:47390/callback"), Set.of("mcp:tools"), null);
        return new ScanAllCommand(ENDPOINT, null, null, null, null, null, false, null, null,
                new SignedInSessionCommand(List.of(new CommandCookie("target", "/", "sid", "abc")), true, client));
    }

    private static CheckAccessCommand command(Boolean useBurpNetworking, CommandIdentities identities) {
        return new CheckAccessCommand(ENDPOINT, TransportType.STREAMABLE_HTTP,
                new CommandAuth("alice-token", Map.of()), useBurpNetworking, identities);
    }
}
