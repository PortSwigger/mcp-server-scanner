package com.mcpscanner.client;

import burp.api.montoya.http.message.HttpRequestResponse;
import com.mcpscanner.auth.BearerTokenAuthStrategy;
import com.mcpscanner.config.ClientIdentityProvider;
import com.mcpscanner.logging.McpEventLog;
import com.mcpscanner.mcp.McpToolDefinition;
import com.mcpscanner.testutil.ClosedPort;
import com.mcpscanner.testutil.MontoyaTestFactory;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import java.io.IOException;
import java.time.Duration;
import java.util.stream.Stream;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.junit.jupiter.api.Assertions.assertTimeoutPreemptively;

@Timeout(30)
class IsolatedCatalogDiscoveryTest {

    private static final String ALICE = "Bearer alice";
    private static final String BOB = "Bearer bob";
    private static final String BOB_ONLY_TOOL = "bob_only";

    private final JdkProtocolHttpTransport sharedTransport = new JdkProtocolHttpTransport(McpHttpClients.upstream());
    private final McpClientManager primary = new McpClientManager(McpEventLog.noop(),
            ClientIdentityProvider.defaults(), sharedTransport);
    private final IsolatedCatalogDiscovery discovery = new IsolatedCatalogDiscovery(McpEventLog.noop(),
            ClientIdentityProvider.defaults(), sharedTransport, ScannerSessionSettings.defaults());
    private McpFixtureServer server;

    @BeforeEach
    void installMontoya() {
        MontoyaTestFactory.install();
    }

    @AfterEach
    void shutDown() {
        primary.disconnect();
        if (server != null) {
            server.close();
        }
    }

    static Stream<Arguments> transports() {
        return Stream.of(
                Arguments.of(TransportType.MODERN_HTTP, McpFixtureProfile.modernOnly()),
                Arguments.of(TransportType.STREAMABLE_HTTP, McpFixtureProfile.streamable("2025-06-18")),
                Arguments.of(TransportType.SSE, McpFixtureProfile.sseOnly("2024-11-05")));
    }

    @ParameterizedTest(name = "{0}")
    @MethodSource("transports")
    void listsTheCatalogTheIdentityCredentialIsShown(TransportType transport, McpFixtureProfile profile)
            throws IOException {
        startServer(profile);
        primary.connect(config(transport, "alice"));

        ConnectResult listing = discovery.discover(config(transport, "bob"));

        assertThat(listing.tools()).extracting(McpToolDefinition::name)
                .containsExactlyInAnyOrder(McpFixtureServer.toolName(), BOB_ONLY_TOOL);
    }

    @Test
    void recordsTheToolsListExchangeSentWithTheIdentitysCredential() throws IOException {
        startServer(McpFixtureProfile.streamable("2025-06-18"));

        RecordedCatalog recorded = discovery.discoverRecorded(config(TransportType.STREAMABLE_HTTP, "bob"));

        assertThat(recorded.catalog().tools()).extracting(McpToolDefinition::name).contains(BOB_ONLY_TOOL);
        assertThat(recorded.toolsList()).singleElement().satisfies(exchange -> {
            assertThat(exchange.request().headerValue("Authorization")).isEqualTo(BOB);
            assertThat(exchange.request().bodyToString()).contains("tools/list");
            assertThat(exchange.response().bodyToString()).contains(BOB_ONLY_TOOL);
        });
    }

    @Test
    void recordsAStreamedReplyLeftOpenAfterAnsweringTheServersPingFirst() throws IOException {
        startServer(McpFixtureProfile.streamable("2025-06-18").pingingBeforeReplies());

        RecordedCatalog recorded = assertTimeoutPreemptively(Duration.ofSeconds(15),
                () -> discovery.discoverRecorded(config(TransportType.STREAMABLE_HTTP, "bob")));

        assertThat(recorded.catalog().tools()).extracting(McpToolDefinition::name).contains(BOB_ONLY_TOOL);
        assertThat(server.pingReplies()).isNotEmpty();
        assertThat(recorded.toolsList()).singleElement().satisfies(exchange -> {
            assertThat(exchange.response().headerValue("Content-Type")).isEqualTo("text/event-stream");
            assertThat(exchange.response().bodyToString()).contains(BOB_ONLY_TOOL);
        });
    }

    @Test
    void recordsALegacySseListingAsThePostThenTheStreamEventThatAnsweredIt() throws IOException {
        startServer(McpFixtureProfile.sseOnly("2024-11-05"));

        RecordedCatalog recorded = discovery.discoverRecorded(config(TransportType.SSE, "bob"));

        assertThat(recorded.catalog().tools()).extracting(McpToolDefinition::name).contains(BOB_ONLY_TOOL);
        assertThat(recorded.toolsList()).hasSize(2);
        HttpRequestResponse post = recorded.toolsList().get(0);
        assertThat(post.request().method()).isEqualTo("POST");
        assertThat(post.request().path()).startsWith("/messages?session=");
        assertThat(post.request().headerValue("Authorization")).isEqualTo(BOB);
        assertThat(post.request().bodyToString()).contains("tools/list");
        assertThat(post.response().statusCode()).isEqualTo((short) 202);
        HttpRequestResponse stream = recorded.toolsList().get(1);
        assertThat(stream.request().method()).isEqualTo("GET");
        assertThat(stream.request().url()).isEqualTo(server.endpoint());
        assertThat(stream.request().headerValue("Authorization")).isEqualTo(BOB);
        assertThat(stream.response().statusCode()).isEqualTo((short) 200);
        assertThat(stream.response().headerValue("Content-Type")).isEqualTo("text/event-stream");
        assertThat(stream.response().bodyToString()).startsWith("event: message\ndata: ")
                .contains(BOB_ONLY_TOOL).containsOnlyOnce("data:").endsWith("\n\n");
    }

    @ParameterizedTest(name = "{0}")
    @MethodSource("transports")
    void leavesThePrimarySessionConnectedWithItsOwnCredentials(TransportType transport, McpFixtureProfile profile)
            throws IOException {
        startServer(profile);
        primary.connect(config(transport, "alice"));
        long generation = primary.scannerSession().connectionGeneration();

        discovery.discover(config(transport, "bob"));

        assertThat(primary.isConnected()).isTrue();
        assertThat(primary.scannerSession().connectionGeneration()).isEqualTo(generation);
        assertThat(primary.scannerSession().scannerHeaders()).containsEntry("Authorization", ALICE);
        assertThat(primary.scannerSession().catalog("tools/list", null).error()).isNull();
        assertThat(server.callsTo("tools/list")).extracting(McpFixtureServer.ObservedCall::authorization)
                .containsExactly(ALICE, BOB, ALICE);
    }

    @Test
    void endsOnlyTheIdentitySessionOnInitializeBasedHttp() throws IOException {
        startServer(McpFixtureProfile.streamable("2025-06-18"));
        primary.connect(config(TransportType.STREAMABLE_HTTP, "alice"));

        discovery.discover(config(TransportType.STREAMABLE_HTTP, "bob"));

        assertThat(server.sessionDeleteAuthorizations()).containsExactly(BOB);
    }

    @Test
    void failureIsReportedWithoutDisturbingThePrimary() throws IOException {
        startServer(McpFixtureProfile.modernOnly());
        primary.connect(config(TransportType.MODERN_HTTP, "alice"));

        assertThatThrownBy(() -> discovery.discover(new McpServerConfig(closedEndpoint(), TransportType.MODERN_HTTP,
                new BearerTokenAuthStrategy("bob")))).isInstanceOf(RuntimeException.class);

        assertThat(primary.isConnected()).isTrue();
        assertThat(primary.scannerSession().scannerHeaders()).containsEntry("Authorization", ALICE);
    }

    @Test
    void connectListenersLearnTheResolvedTransportAndCatalog() throws IOException {
        startServer(McpFixtureProfile.streamable("2025-06-18"));
        java.util.List<PrimaryConnection> connections = new java.util.ArrayList<>();
        primary.addConnectListener(connections::add);

        primary.connect(config(TransportType.AUTO, "alice"));

        assertThat(connections).singleElement().satisfies(connection -> {
            assertThat(connection.endpoint()).isEqualTo(server.endpoint());
            assertThat(connection.transport()).isEqualTo(TransportType.STREAMABLE_HTTP);
            assertThat(connection.catalog().tools()).extracting(McpToolDefinition::name)
                    .containsExactly(McpFixtureServer.toolName());
        });
    }

    @ParameterizedTest(name = "{0}")
    @MethodSource("transports")
    void connectListenersReceiveThePrimarysOwnToolsListExchangeWithoutAnotherListing(TransportType transport,
                                                                                   McpFixtureProfile profile)
            throws IOException {
        startServer(profile);
        java.util.List<PrimaryConnection> connections = new java.util.ArrayList<>();
        primary.addConnectListener(connections::add);

        primary.connect(config(transport, "alice"));

        assertThat(server.callsTo("tools/list")).hasSize(1);
        assertThat(connections).singleElement().satisfies(connection -> {
            assertThat(connection.toolsList()).isNotEmpty();
            HttpRequestResponse listing = connection.toolsList().get(0);
            assertThat(listing.request().headerValue("Authorization")).isEqualTo(ALICE);
            assertThat(listing.request().bodyToString()).contains("tools/list");
            assertThat(connection.toolsList().get(connection.toolsList().size() - 1).response().bodyToString())
                    .contains(McpFixtureServer.toolName());
        });
    }

    @Test
    void eachConnectRecordsItsOwnToolsListAndLaterListingsAreNotRecorded() throws IOException {
        startServer(McpFixtureProfile.streamable("2025-06-18"));
        java.util.List<PrimaryConnection> connections = new java.util.ArrayList<>();
        primary.addConnectListener(connections::add);

        primary.connect(config(TransportType.STREAMABLE_HTTP, "alice"));
        primary.scannerSession().catalog("tools/list", null);
        primary.connect(config(TransportType.STREAMABLE_HTTP, "bob"));

        assertThat(connections).hasSize(2);
        assertThat(connections.get(0).toolsList()).singleElement().satisfies(exchange ->
                assertThat(exchange.request().headerValue("Authorization")).isEqualTo(ALICE));
        assertThat(connections.get(1).toolsList()).singleElement().satisfies(exchange -> {
            assertThat(exchange.request().headerValue("Authorization")).isEqualTo(BOB);
            assertThat(exchange.response().bodyToString()).contains(BOB_ONLY_TOOL);
        });
    }

    private void startServer(McpFixtureProfile profile) throws IOException {
        server = new McpFixtureServer(profile);
        server.grantToolTo(BOB, BOB_ONLY_TOOL);
    }

    private McpServerConfig config(TransportType transport, String token) {
        return new McpServerConfig(server.endpoint(), transport, new BearerTokenAuthStrategy(token));
    }

    private static String closedEndpoint() throws IOException {
        return "http://127.0.0.1:" + ClosedPort.onLoopback() + "/mcp";
    }
}
