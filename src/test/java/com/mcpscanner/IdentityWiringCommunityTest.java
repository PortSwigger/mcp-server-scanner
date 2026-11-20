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
import com.mcpscanner.testutil.MontoyaTestFactory;
import com.mcpscanner.testutil.ScriptedBurpHttp;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.time.Duration;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;
import static org.awaitility.Awaitility.await;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.argThat;
import static org.mockito.Mockito.RETURNS_DEEP_STUBS;
import static org.mockito.Mockito.after;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

class IdentityWiringCommunityTest {

    private static final String ENDPOINT = "https://mcp.example.test/mcp";
    private static final Duration QUIET_PERIOD = Duration.ofMillis(500);

    private final MontoyaApi api = mock(MontoyaApi.class, RETURNS_DEEP_STUBS);
    private final Http http = mock(Http.class);
    private final PersistedObject savedSettings = mock(PersistedObject.class);
    private final ScriptedBurpHttp fakeServer = ScriptedBurpHttp.fakeMcpServer();
    private final ShutdownHooks shutdown = new ShutdownHooks(failure -> {
        throw new AssertionError(failure);
    });
    private ExtensionFoundation foundation;
    private ConnectionWiring connection;
    private Set<Thread> threadsBeforeConnect;

    @BeforeEach
    void wireTheCommunityIdentityParts() {
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
        IdentityWiring identities = IdentityWiring.create(foundation,
                OAuthWiring.create(api, foundation, connection.burpHttp()));
        connection.start(shutdown);
        identities.addShutdownHooks(shutdown);
        threadsBeforeConnect = Thread.getAllStackTraces().keySet();
    }

    @AfterEach
    void unload() {
        shutdown.extensionUnloaded();
    }

    @Test
    void connectingWithASavedComparedUserDiscoversNothingAsThem() {
        Identity bob = foundation.identities().add(Identity.create("bob", IdentityRole.PEER, IdentityAuthKind.BEARER));
        foundation.identities().setCredential(bob.id(), new BearerTokenAuthStrategy("bob"));

        connection.clientManager().connect(new McpServerConfig(ENDPOINT, TransportType.MODERN_HTTP,
                new BearerTokenAuthStrategy("alice")));

        verify(http, after(QUIET_PERIOD.toMillis()).never()).sendRequest(
                argThat(request -> "Bearer bob".equals(request.headerValue("Authorization"))),
                any(RequestOptions.class));
        await().during(QUIET_PERIOD).atMost(QUIET_PERIOD.multipliedBy(2))
                .until(() -> newThreadsNamed("mcp-identity-discovery").isEmpty());
    }

    private Set<String> newThreadsNamed(String name) {
        return Thread.getAllStackTraces().keySet().stream().filter(thread -> !threadsBeforeConnect.contains(thread))
                .map(Thread::getName).filter(name::equals).collect(java.util.stream.Collectors.toSet());
    }
}
