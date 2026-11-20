package com.mcpscanner.signedin;

import com.mcpscanner.checks.shared.oauth.SessionCookie;
import burp.api.montoya.logging.Logging;
import com.mcpscanner.checks.api.RegisteredClientName;
import com.mcpscanner.checks.api.ScannerClient;
import com.mcpscanner.checks.shared.oauth.ClientSecret;
import com.mcpscanner.checks.shared.oauth.ClientSecretMethod;
import com.mcpscanner.checks.api.SignedInConsent;
import com.mcpscanner.checks.api.SignedInProbe;
import com.mcpscanner.config.ExtensionConfigStore;
import com.mcpscanner.config.SignedInConsentSetting;
import com.mcpscanner.testutil.InMemoryPersistedObject;
import com.mcpscanner.testutil.InMemoryPreferences;
import org.junit.jupiter.api.Test;

import java.net.URI;
import java.time.Clock;
import java.util.List;
import java.util.Optional;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;

class BurpSignedInConsentTest {

    private static final URI AUTHORIZE = URI.create("https://auth.example.com/authorize");

    private final SignedInConsentSetting setting = new SignedInConsentSetting(
            new ExtensionConfigStore(InMemoryPersistedObject.create(), new InMemoryPreferences(), mock(Logging.class)));
    private final ConnectSignIns signIns = new ConnectSignIns();
    private final BrowserConsentObservations observations = new BrowserConsentObservations();
    private final SignedInConsent consent = new BurpSignedInConsent(setting, signIns,
            new CookieJarSessions(() -> List.of(JarCookie.session("auth.example.com", "/", "sid", "abc")), cookie -> false,
                    Clock.systemUTC()),
            observations);

    @Test
    void optedOutByDefaultAndOffersNothing() {
        signIns.signedIn(ConnectSignInsTest.signIn("client-1"));
        signIns.connected(ConnectSignInsTest.connection("https://mcp.example.com/mcp"));
        observations.record(BrowserConsentObservationsTest.observation(AUTHORIZE, SignedInProbe.SAME_NAME));

        assertThat(consent.optedIn()).isFalse();
        assertThat(consent.cookieSession(AUTHORIZE)).isEmpty();
        assertThat(consent.scannerClient()).isEmpty();
        assertThat(consent.browserObservations(AUTHORIZE)).isEmpty();
    }

    @Test
    void optedInOffersTheCookieJarSession() {
        setting.optIn(true);

        assertThat(consent.optedIn()).isTrue();
        assertThat(consent.cookieSession(AUTHORIZE)).get()
                .satisfies(session -> assertThat(session.cookies()).extracting(SessionCookie::name, SessionCookie::value)
                        .contains(org.assertj.core.groups.Tuple.tuple("sid", "abc")));
    }

    @Test
    void optedInOffersTheClientOfTheConnectSignIn() {
        setting.optIn(true);
        signIns.signedIn(ConnectSignInsTest.signIn("client-1"));
        signIns.connected(ConnectSignInsTest.connection("https://mcp.example.com/mcp"));

        assertThat(consent.scannerClient()).contains(new ScannerClient(URI.create("https://auth.example.com"), "client-1",
                RegisteredClientName.of("MCP Scanner"),
                URI.create("http://127.0.0.1:4000/callback"), Set.of("read"), Optional.of("software")));
    }

    @Test
    void optedInOffersTheConnectSignInsClientSecretAsBasicAuthenticationWithoutPrintingIt() {
        setting.optIn(true);
        signIns.signedIn(ConnectSignInsTest.signInWithSecret("client-1", "connect-secret"));
        signIns.connected(ConnectSignInsTest.connection("https://mcp.example.com/mcp"));

        assertThat(consent.scannerClient()).get().satisfies(client -> {
            assertThat(client.secret()).contains(new ClientSecret("connect-secret", ClientSecretMethod.BASIC));
            assertThat(client.toString()).doesNotContain("connect-secret");
        });
    }

    @Test
    void optedInOffersTheBrowserObservations() {
        setting.optIn(true);
        observations.record(BrowserConsentObservationsTest.observation(AUTHORIZE, SignedInProbe.SAME_NAME));

        assertThat(consent.browserObservations(AUTHORIZE)).singleElement()
                .extracting(observation -> observation.probe()).isEqualTo(SignedInProbe.SAME_NAME);
    }
}
