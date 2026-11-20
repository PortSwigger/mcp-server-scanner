package com.mcpscanner.checks.shared.oauth;

import com.mcpscanner.logging.McpEventLog;
import com.mcpscanner.testutil.MontoyaTestFactory;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.net.URI;
import java.util.List;
import java.util.Optional;

import static com.mcpscanner.checks.shared.oauth.ScriptedHttp.status;
import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.argThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;

class TokenRevocationTest {

    private static final URI TOKEN_ENDPOINT = URI.create("https://as.example/token");
    private static final URI REVOKE = URI.create("https://as.example/revoke");
    private static final List<IssuedToken> TOKENS = List.of(IssuedToken.access("a1"), IssuedToken.refresh("r1"));

    private final McpEventLog eventLog = mock(McpEventLog.class);
    private ScriptedHttp server;

    @BeforeEach
    void setUp() {
        MontoyaTestFactory.install();
        server = new ScriptedHttp();
    }

    private TokenRevocation revocation(Optional<URI> endpoint) {
        return new TokenRevocation(server.oauth(), endpoint, TOKEN_ENDPOINT, eventLog);
    }

    @Test
    void revokesEveryTokenWithItsTypeHintAndTheClientId() {
        server.on("POST", REVOKE.toString(), status(200));

        revocation(Optional.of(REVOKE)).revoke("client-1", TOKENS);

        assertThat(server.sentTo(REVOKE.toString())).extracting(request -> request.bodyToString()).containsExactly(
                "token=a1&token_type_hint=access_token&client_id=client-1",
                "token=r1&token_type_hint=refresh_token&client_id=client-1");
        verify(eventLog, never()).error(org.mockito.ArgumentMatchers.anyString());
    }

    @Test
    void logsTheTokensItCouldNotRevoke() {
        server.on("POST", REVOKE.toString(), status(400));

        revocation(Optional.of(REVOKE)).revoke("client-1", TOKENS);

        verify(eventLog).error(argThat(message -> message.contains("https://as.example")
                && message.contains("client_id client-1") && message.contains("2 OAuth token(s)")));
    }

    @Test
    void logsEveryTokenWhenTheServerAdvertisesNoRevocationEndpoint() {
        revocation(Optional.empty()).revoke("client-1", TOKENS);

        assertThat(server.sent()).isEmpty();
        verify(eventLog).error(argThat(message -> message.contains("no revocation endpoint")
                && message.contains("2 OAuth token(s)")));
    }

    @Test
    void doesNothingWithoutTokens() {
        revocation(Optional.empty()).revoke("client-1", List.of());

        verify(eventLog, never()).error(org.mockito.ArgumentMatchers.anyString());
    }

    @Test
    void authenticatesAConfidentialClientTheWayItWasIssued() {
        server.on("POST", REVOKE.toString(), status(200));

        revocation(Optional.of(REVOKE)).revoke(new ClientCredentials("client-1",
                Optional.of(new ClientSecret("s1", ClientSecretMethod.POST))), List.of(IssuedToken.access("a1")));

        assertThat(server.sentTo(REVOKE.toString())).extracting(request -> request.bodyToString())
                .containsExactly("token=a1&token_type_hint=access_token&client_id=client-1&client_secret=s1");
    }
}
