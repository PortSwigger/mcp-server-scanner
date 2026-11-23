package com.mcpscanner;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.Http;
import burp.api.montoya.http.RequestOptions;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.sessions.CookieJar;
import com.mcpscanner.auth.AuthStrategy;
import com.mcpscanner.auth.BearerTokenAuthStrategy;
import com.mcpscanner.auth.NoAuthStrategy;
import com.mcpscanner.auth.oauth.OAuthAuthorizationFlow;
import com.mcpscanner.auth.oauth.OAuthSignIn;
import com.mcpscanner.auth.oauth.SignInListener;
import com.mcpscanner.checks.api.BrowserConsentObservation;
import com.mcpscanner.checks.api.ScannerClient;
import com.mcpscanner.checks.api.SignedInProbe;
import com.mcpscanner.client.McpServerConfig;
import com.mcpscanner.client.TransportType;
import com.mcpscanner.testutil.InMemoryPersistedObject;
import com.mcpscanner.testutil.InMemoryPreferences;
import com.mcpscanner.testutil.MontoyaTestFactory;
import com.mcpscanner.testutil.ScriptedBurpHttp;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;

import java.net.URI;
import java.time.Duration;
import java.util.List;
import java.util.Optional;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.RETURNS_DEEP_STUBS;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

class SignedInConsentWiringTest {

    private static final URI AUTHORIZE = URI.create("https://auth.example.test/authorize");

    private final MontoyaApi api = mock(MontoyaApi.class, RETURNS_DEEP_STUBS);
    private final Http http = mock(Http.class);
    private final CookieJar cookieJar = mock(CookieJar.class);
    private final ScriptedBurpHttp fakeServer = ScriptedBurpHttp.fakeMcpServer();
    private final OAuthAuthorizationFlow connectFlow = mock(OAuthAuthorizationFlow.class);
    private final OAuthAuthorizationFlow identitySignInFlow = mock(OAuthAuthorizationFlow.class);
    private ExtensionFoundation foundation;
    private ConnectionWiring connection;
    private SignedInConsentWiring signedIn;

    @BeforeEach
    void setUp() {
        MontoyaTestFactory.install();
        burp.api.montoya.persistence.PersistedObject savedSettings = InMemoryPersistedObject.create();
        when(api.persistence().extensionData()).thenReturn(savedSettings);
        when(api.persistence().preferences()).thenReturn(new InMemoryPreferences());
        when(api.http()).thenReturn(http);
        when(http.cookieJar()).thenReturn(cookieJar);
        when(cookieJar.cookies()).thenReturn(List.of());
        when(http.sendRequest(any(HttpRequest.class), any(RequestOptions.class)))
                .thenAnswer(invocation -> fakeServer.sendRequest(invocation.getArgument(0, HttpRequest.class),
                        invocation.getArgument(1, RequestOptions.class)));
        foundation = ExtensionFoundation.create(api);
        connection = ConnectionWiring.create(api, foundation);
        OAuthWiring oauth = new OAuthWiring(null, null, null, connectFlow, identitySignInFlow, null, null);
        signedIn = SignedInConsentWiring.create(api, foundation, connection, oauth);
    }

    @Test
    void listensOnlyToTheConnectSignIn() {
        verify(connectFlow).addSignInListener(any(SignInListener.class));
        verify(identitySignInFlow, never()).addSignInListener(any(SignInListener.class));
    }

    @Test
    void isOptedOutUntilTheProjectSettingIsOn() {
        assertThat(signedIn.consent().optedIn()).isFalse();

        signedIn.setting().optIn(true);

        assertThat(signedIn.consent().optedIn()).isTrue();
    }

    @Test
    void offersTheScannerClientOfTheConnectSignInUntilDisconnect() {
        signedIn.setting().optIn(true);
        connectSignInListener().signedIn(signIn());
        connect();

        assertThat(signedIn.consent().scannerClient()).map(ScannerClient::clientId).contains("scanner-client");

        connection.clientManager().disconnect();

        assertThat(signedIn.consent().scannerClient()).isEmpty();
    }

    @Test
    void aScopeStepUpAfterConnectWidensTheOfferedScannerClientsGrant() {
        signedIn.setting().optIn(true);
        connectSignInListener().signedIn(signIn());
        connect();

        connectSignInListener().scopesWidened(signIn().withGrantedScopes(Set.of("read", "write")));

        assertThat(signedIn.consent().scannerClient()).map(ScannerClient::grantedScopes)
                .contains(Set.of("read", "write"));
    }

    @Test
    void aSignInOfAFailedOAuthConnectIsNotOfferedAfterABearerConnect() {
        signedIn.setting().optIn(true);
        connection.clientManager().beginConnectAttempt();
        connectSignInListener().signedIn(signIn());
        assertThatThrownBy(() -> connect(failingDiscovery())).isInstanceOf(IllegalStateException.class);

        connection.clientManager().beginConnectAttempt();
        connect(new BearerTokenAuthStrategy("bearer-token"));

        assertThat(signedIn.consent().scannerClient()).isEmpty();
    }

    @Test
    void forgetsTheScannerClientWhenTheEndpointChanges() {
        signedIn.setting().optIn(true);
        connectSignInListener().signedIn(signIn());
        connect();

        foundation.configStore().setEndpoint("https://other.example.test/mcp");

        assertThat(signedIn.consent().scannerClient()).isEmpty();
    }

    @Test
    void forgetsAPendingSignInWhenTheEndpointChanges() {
        signedIn.setting().optIn(true);
        connectSignInListener().signedIn(signIn());
        foundation.configStore().setEndpoint("https://other.example.test/mcp");

        connect();

        assertThat(signedIn.consent().scannerClient()).isEmpty();
    }

    @Test
    void doesNotOfferASignInForAnotherEndpoint() {
        signedIn.setting().optIn(true);
        connectSignInListener().signedIn(signIn());

        connection.clientManager().connect(new McpServerConfig("https://mcp.example.test/other",
                TransportType.STREAMABLE_HTTP, new NoAuthStrategy()));

        assertThat(signedIn.consent().scannerClient()).isEmpty();
    }

    @Test
    void forgetsBrowserObservationsWhenTheEndpointChanges() {
        signedIn.setting().optIn(true);
        signedIn.browserObservations().record(observation());

        foundation.configStore().setEndpoint("https://other.example.test/mcp");

        assertThat(signedIn.consent().browserObservations(AUTHORIZE)).isEmpty();
    }

    @Test
    void forgetsBrowserObservationsOnDisconnect() {
        signedIn.setting().optIn(true);
        connect();
        signedIn.browserObservations().record(observation());

        connection.clientManager().disconnect();

        assertThat(signedIn.consent().browserObservations(AUTHORIZE)).isEmpty();
    }

    @Test
    void readsCookiesFromBurpsCookieJar() {
        signedIn.setting().optIn(true);

        signedIn.consent().cookieSession(AUTHORIZE);

        verify(cookieJar).cookies();
    }

    private SignInListener connectSignInListener() {
        ArgumentCaptor<SignInListener> listener = ArgumentCaptor.forClass(SignInListener.class);
        verify(connectFlow).addSignInListener(listener.capture());
        return listener.getValue();
    }

    private void connect() {
        connect(new NoAuthStrategy());
    }

    private void connect(AuthStrategy auth) {
        connection.clientManager().connect(new McpServerConfig("https://mcp.example.test/mcp",
                TransportType.STREAMABLE_HTTP, auth));
    }

    private static AuthStrategy failingDiscovery() {
        return () -> {
            throw new IllegalStateException("discovery failed");
        };
    }

    private static BrowserConsentObservation observation() {
        return new BrowserConsentObservation(SignedInProbe.SAME_NAME, AUTHORIZE, "MCP Scanner",
                URI.create("http://localhost:4100/callback"), Optional.of(Duration.ofMillis(200)));
    }

    private static OAuthSignIn signIn() {
        return new OAuthSignIn(URI.create("https://auth.example.test"), AUTHORIZE, Optional.empty(), "scanner-client",
                Optional.of("MCP Scanner"), URI.create("http://127.0.0.1:4000/callback"), Set.of("read"), Optional.empty(),
                URI.create("https://mcp.example.test/mcp"));
    }
}
