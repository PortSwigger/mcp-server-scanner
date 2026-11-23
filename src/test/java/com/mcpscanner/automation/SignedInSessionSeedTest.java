package com.mcpscanner.automation;

import burp.api.montoya.http.sessions.CookieJar;
import com.mcpscanner.auth.oauth.OAuthSignIn;
import org.junit.jupiter.api.Test;

import java.net.URI;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.time.ZonedDateTime;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;

class SignedInSessionSeedTest {

    private static final Instant NOW = Instant.parse("2026-11-18T10:00:00Z");

    private final CookieJar jar = mock(CookieJar.class);
    private static final String ENDPOINT = "http://127.0.0.1:4100/mcp";
    private static final CommandScannerClient SCANNER_CLIENT = new CommandScannerClient(
            URI.create("http://127.0.0.1:4100"), URI.create("http://127.0.0.1:4100/authorize"),
            URI.create("http://127.0.0.1:4100/register"), "mcp-server-scanner_AbCd", "MCP Server Scanner",
            URI.create("http://127.0.0.1:47390/callback"), Set.of("mcp:tools"), "mcp-server-scanner");

    private final List<Boolean> optIns = new ArrayList<>();
    private final List<OAuthSignIn> signIns = new ArrayList<>();
    private final SignedInSessionSeed seed = new SignedInSessionSeed(() -> jar, optIns::add, signIns::add,
            Clock.fixed(NOW, ZoneOffset.UTC));

    @Test
    void putsEveryCookieInBurpsCookieJar() {
        seed.apply(new SignedInSessionCommand(List.of(
                new CommandCookie("auth.example.test", "/", "sid", "abc"),
                new CommandCookie("example.test", "/oauth", "csrf", "xyz")), true));

        ZonedDateTime expiry = NOW.atZone(ZoneOffset.UTC).plus(SignedInSessionSeed.COOKIE_LIFETIME);
        verify(jar).setCookie("sid", "abc", "/", "auth.example.test", expiry);
        verify(jar).setCookie("csrf", "xyz", "/oauth", "example.test", expiry);
    }

    @Test
    void turnsTheSettingOnWhenAsked() {
        seed.apply(new SignedInSessionCommand(List.of(), true));

        assertThat(optIns).containsExactly(true);
    }

    @Test
    void leavesTheSettingAloneWhenNotAsked() {
        seed.apply(new SignedInSessionCommand(List.of(), null));

        assertThat(optIns).isEmpty();
    }

    @Test
    void answersHowManyCookiesItSetAndWhetherTheProjectIsOptedInButNoValue() {
        SignedInSessionSeeded seeded = seed.apply(new SignedInSessionCommand(
                List.of(new CommandCookie("auth.example.test", "/", "sid", "secret-value")), true));

        assertThat(seeded).isEqualTo(new SignedInSessionSeeded(1, true));
        assertThat(seeded.toString()).doesNotContain("secret-value");
    }

    @Test
    void refusesACookieWithoutADomainOrName() {
        assertThatThrownBy(() -> new CommandCookie(" ", "/", "sid", "abc"))
                .isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> new CommandCookie("auth.example.test", "/", null, "abc"))
                .isInstanceOf(IllegalArgumentException.class);
        verifyNoInteractions(jar);
    }

    @Test
    void defaultsAMissingPathToTheRoot() {
        assertThat(new CommandCookie("auth.example.test", null, "sid", "abc").path()).isEqualTo("/");
    }

    @Test
    void beforeConnectSignsTheScannerClientInForTheEndpointBeingConnected() {
        seed.beforeConnect(new SignedInSessionCommand(List.of(), true, SCANNER_CLIENT), ENDPOINT);

        assertThat(signIns).containsExactly(new OAuthSignIn(URI.create("http://127.0.0.1:4100"),
                URI.create("http://127.0.0.1:4100/authorize"), Optional.of(URI.create("http://127.0.0.1:4100/register")),
                "mcp-server-scanner_AbCd", Optional.of("MCP Server Scanner"), URI.create("http://127.0.0.1:47390/callback"),
                Set.of("mcp:tools"), Optional.of("mcp-server-scanner"), URI.create(ENDPOINT)));
    }

    @Test
    void beforeConnectAlsoSeedsTheCookiesAndOptIn() {
        seed.beforeConnect(new SignedInSessionCommand(
                List.of(new CommandCookie("127.0.0.1", "/", "sid", "abc")), true, SCANNER_CLIENT), ENDPOINT);

        verify(jar).setCookie("sid", "abc", "/", "127.0.0.1",
                NOW.atZone(ZoneOffset.UTC).plus(SignedInSessionSeed.COOKIE_LIFETIME));
        assertThat(optIns).containsExactly(true);
    }

    @Test
    void aScannerClientWithoutRegistrationEndpointOrSoftwareIdSignsInWithout() {
        CommandScannerClient bare = new CommandScannerClient(URI.create("http://127.0.0.1:4100"),
                URI.create("http://127.0.0.1:4100/authorize"), null, "client-1", "MCP Server Scanner",
                URI.create("http://127.0.0.1:47390/callback"), null, null);

        seed.beforeConnect(new SignedInSessionCommand(List.of(), true, bare), ENDPOINT);

        assertThat(signIns).singleElement().satisfies(signIn -> {
            assertThat(signIn.registrationEndpoint()).isEmpty();
            assertThat(signIn.softwareId()).isEmpty();
            assertThat(signIn.grantedScopes()).isEmpty();
        });
    }

    @Test
    void beforeConnectSignsNobodyInWithoutAScannerClient() {
        seed.beforeConnect(new SignedInSessionCommand(List.of(), true), ENDPOINT);

        assertThat(signIns).isEmpty();
    }

    @Test
    void applyingTheSessionAloneSignsNobodyIn() {
        seed.apply(new SignedInSessionCommand(List.of(), true, SCANNER_CLIENT));

        assertThat(signIns).isEmpty();
    }
}
