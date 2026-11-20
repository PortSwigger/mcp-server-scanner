package com.mcpscanner.signedin;

import com.mcpscanner.auth.oauth.OAuthSignIn;
import com.mcpscanner.client.ConnectResult;
import com.mcpscanner.client.PrimaryConnection;
import com.mcpscanner.client.TransportType;
import com.mcpscanner.mcp.ServerMetadata;
import org.junit.jupiter.api.Test;

import java.net.URI;
import java.util.List;
import java.util.Optional;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;

class ConnectSignInsTest {

    private static final String ENDPOINT = "https://mcp.example.com/mcp";

    private final ConnectSignIns signIns = new ConnectSignIns();

    @Test
    void knowsNoSignInBeforeConnect() {
        signIns.signedIn(signIn("client-1"));

        assertThat(signIns.current()).isEmpty();
    }

    @Test
    void theSignInOfTheConnectThatSucceededIsCurrent() {
        signIns.signedIn(signIn("client-1"));
        signIns.connected(connection(ENDPOINT));

        assertThat(signIns.current()).map(OAuthSignIn::clientId).contains("client-1");
    }

    @Test
    void reconnectingKeepsTheNewSignInThoughTheOldConnectionDisconnectsAfterIt() {
        signIns.signedIn(signIn("client-1"));
        signIns.connected(connection(ENDPOINT));
        signIns.connectAttemptStarted();
        signIns.signedIn(signIn("client-2"));
        signIns.disconnected();
        signIns.connected(connection(ENDPOINT));

        assertThat(signIns.current()).map(OAuthSignIn::clientId).contains("client-2");
    }

    @Test
    void disconnectForgetsTheSignIn() {
        signIns.signedIn(signIn("client-1"));
        signIns.connected(connection(ENDPOINT));
        signIns.disconnected();

        assertThat(signIns.current()).isEmpty();
    }

    @Test
    void aConnectWithoutOAuthHasNoSignIn() {
        signIns.signedIn(signIn("client-1"));
        signIns.connected(connection(ENDPOINT));
        signIns.disconnected();
        signIns.connectAttemptStarted();
        signIns.connected(connection(ENDPOINT));

        assertThat(signIns.current()).isEmpty();
    }

    @Test
    void aSignInOfAFailedConnectIsNotPromotedByTheNextConnect() {
        signIns.connectAttemptStarted();
        signIns.signedIn(signIn("client-1"));
        signIns.connectAttemptStarted();
        signIns.connected(connection(ENDPOINT));

        assertThat(signIns.current()).isEmpty();
    }

    @Test
    void aNewConnectAttemptForgetsTheCurrentSignIn() {
        signIns.signedIn(signIn("client-1"));
        signIns.connected(connection(ENDPOINT));
        signIns.connectAttemptStarted();

        assertThat(signIns.current()).isEmpty();
    }

    @Test
    void forgettingClearsBothThePendingAndTheCurrentSignIn() {
        signIns.signedIn(signIn("client-1"));
        signIns.connected(connection(ENDPOINT));
        signIns.signedIn(signIn("client-2"));
        signIns.forget();
        signIns.connected(connection(ENDPOINT));

        assertThat(signIns.current()).isEmpty();
    }

    @Test
    void aSignInForAnotherEndpointIsNotPromoted() {
        signIns.signedIn(signIn("client-1"));
        signIns.connected(connection("https://other.example.com/mcp"));

        assertThat(signIns.current()).isEmpty();
    }

    @Test
    void aSignInForAnotherPathOnTheSameOriginIsNotPromoted() {
        signIns.signedIn(signIn("client-1"));
        signIns.connected(connection("https://mcp.example.com/other"));

        assertThat(signIns.current()).isEmpty();
    }

    @Test
    void aTrailingSlashAndADefaultPortStillMatchTheSignedInEndpoint() {
        signIns.signedIn(signIn("client-1"));
        signIns.connected(connection("https://MCP.example.com:443/mcp/"));

        assertThat(signIns.current()).map(OAuthSignIn::clientId).contains("client-1");
    }

    @Test
    void anUnmatchedConnectDropsThePendingSignIn() {
        signIns.signedIn(signIn("client-1"));
        signIns.connected(connection("https://other.example.com/mcp"));
        signIns.connected(connection(ENDPOINT));

        assertThat(signIns.current()).isEmpty();
    }

    @Test
    void aScopeStepUpWidensTheCurrentSignInsGrant() {
        signIns.signedIn(signIn("client-1"));
        signIns.connected(connection(ENDPOINT));

        signIns.scopesWidened(signIn("client-1", Set.of("read", "write")));

        assertThat(signIns.current()).map(OAuthSignIn::grantedScopes).contains(Set.of("read", "write"));
    }

    @Test
    void aScopeStepUpOfAnotherClientLeavesTheCurrentSignIn() {
        signIns.signedIn(signIn("client-1"));
        signIns.connected(connection(ENDPOINT));

        signIns.scopesWidened(signIn("client-2", Set.of("read", "write")));

        assertThat(signIns.current()).map(OAuthSignIn::grantedScopes).contains(Set.of("read"));
    }

    @Test
    void aScopeStepUpAfterDisconnectPromotesNothing() {
        signIns.signedIn(signIn("client-1"));
        signIns.connected(connection(ENDPOINT));
        signIns.disconnected();

        signIns.scopesWidened(signIn("client-1", Set.of("read", "write")));

        assertThat(signIns.current()).isEmpty();
    }

    static PrimaryConnection connection(String endpoint) {
        return new PrimaryConnection(endpoint, TransportType.STREAMABLE_HTTP,
                new ConnectResult(List.of(), List.of(), List.of(), List.of(), ServerMetadata.empty()));
    }

    static OAuthSignIn signIn(String clientId) {
        return signIn(clientId, Set.of("read"));
    }

    static OAuthSignIn signInWithSecret(String clientId, String secret) {
        OAuthSignIn signIn = signIn(clientId);
        return new OAuthSignIn(signIn.issuer(), signIn.authorizationEndpoint(), signIn.registrationEndpoint(),
                clientId, signIn.clientName(), signIn.redirectUri(), signIn.grantedScopes(), signIn.softwareId(),
                signIn.resource(), Optional.of(secret));
    }

    static OAuthSignIn signIn(String clientId, Set<String> grantedScopes) {
        return new OAuthSignIn(URI.create("https://auth.example.com"), URI.create("https://auth.example.com/authorize"),
                Optional.of(URI.create("https://auth.example.com/register")), clientId, Optional.of("MCP Scanner"),
                URI.create("http://127.0.0.1:4000/callback"), grantedScopes, Optional.of("software"),
                URI.create(ENDPOINT));
    }
}
