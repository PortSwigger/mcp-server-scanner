package com.mcpscanner.signedin;

import burp.api.montoya.http.message.requests.HttpRequest;
import com.fasterxml.jackson.databind.JsonNode;
import com.mcpscanner.auth.oauth.ActiveCallbackListeners;
import com.mcpscanner.auth.oauth.OAuthSignIn;
import com.mcpscanner.checks.api.BrowserConsentObservation;
import com.mcpscanner.checks.api.SignedInProbe;
import com.mcpscanner.checks.shared.oauth.ProbeClientRegistrar;
import com.mcpscanner.checks.shared.oauth.ScriptedHttp;
import com.mcpscanner.logging.McpEventLog;
import com.mcpscanner.mcp.McpObjectMapper;
import com.mcpscanner.performance.RequestBudgets;
import com.mcpscanner.testutil.MontoyaTestFactory;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.net.URI;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneId;
import java.time.ZoneOffset;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.atomic.AtomicInteger;

import static com.mcpscanner.checks.shared.oauth.ScriptedHttp.json;
import static com.mcpscanner.checks.shared.oauth.ScriptedHttp.status;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class BrowserConsentProbesTest {

    private static final URI AUTHORIZE = URI.create("https://auth.example.test/authorize");
    private static final String REGISTER = "https://auth.example.test/register";
    private static final String ATTACKER_REGISTER = "https://attacker.example.net/register";
    private static final String REGISTRATION_TOKEN = "registration-token-never-to-log";
    private static final Duration STEP = Duration.ofMillis(300);
    private static final Duration SHORT_WAIT = Duration.ofMillis(150);

    private final ScriptedHttp http = new ScriptedHttp();
    private final ScriptedBrowser browser = new ScriptedBrowser();
    private final ActiveCallbackListeners listeners = new ActiveCallbackListeners();
    private final BrowserConsentObservations observations = new BrowserConsentObservations();
    private final McpEventLog log = new McpEventLog(null);
    private final AtomicInteger issued = new AtomicInteger();

    @BeforeEach
    void setUp() {
        MontoyaTestFactory.install();
        http.on("POST", REGISTER, request -> registered("probe-" + issued.incrementAndGet()));
        http.on("DELETE", REGISTER + "/probe-1", status(204));
        http.on("DELETE", REGISTER + "/probe-2", status(204));
    }

    @AfterEach
    void tearDown() {
        listeners.closeAll();
    }

    @Test
    void aServerThatAsksForConsentShowsExactlyOneTabAndRecordsNoCode() {
        browser.replying(ScriptedBrowser.Reply.CONSENT_PAGE);

        probes().run(signIn());

        assertThat(browser.opened()).hasSize(1);
        assertThat(observations.at(AUTHORIZE)).singleElement().satisfies(observation -> {
            assertThat(observation.probe()).isEqualTo(SignedInProbe.SAME_NAME);
            assertThat(observation.clientName()).isEqualTo("MCP Scanner");
            assertThat(observation.codeArrivedAfter()).isEmpty();
        });
        RequestBudgets.assertWithin("Browser consent fallback, server that asks for consent", http.sentUrls());
    }

    @Test
    void aCodeWithinTheWaitIsRecordedWithItsArrivalTimeThenAFreshNameIsTried() {
        browser.replying(ScriptedBrowser.Reply.CODE);

        probes().run(signIn());

        assertThat(observations.at(AUTHORIZE)).satisfiesExactly(
                sameName -> {
                    assertThat(sameName.probe()).isEqualTo(SignedInProbe.SAME_NAME);
                    assertThat(sameName.clientName()).isEqualTo("MCP Scanner");
                    assertThat(sameName.codeArrivedAfter()).contains(STEP);
                },
                freshName -> {
                    assertThat(freshName.probe()).isEqualTo(SignedInProbe.FRESH_NAME);
                    assertThat(freshName.clientName()).isNotBlank().isNotEqualTo("MCP Scanner");
                    assertThat(freshName.codeArrivedAfter()).contains(STEP);
                });
        assertThat(registeredNames()).containsExactly("MCP Scanner",
                observations.at(AUTHORIZE).get(1).clientName());
        RequestBudgets.assertWithin("Browser consent fallback, server that skips consent", http.sentUrls());
    }

    @Test
    void aRegistrationEndpointOffTheIssuerOriginRegistersNothingAndOpensNoTab() {
        http.on("POST", ATTACKER_REGISTER, request -> registered("attacker-client"));

        probes().run(signInRegisteringAt(Optional.of(URI.create(ATTACKER_REGISTER))));

        assertThat(http.sentUrls()).isEmpty();
        assertThat(browser.opened()).isEmpty();
        assertThat(observations.at(AUTHORIZE)).isEmpty();
        assertThat(messages()).anyMatch(message -> message.contains("not run: the authorization server's "
                + "registration endpoint " + ATTACKER_REGISTER + " is not on the origin of its issuer "
                + "https://auth.example.test"));
    }

    @Test
    void anAuthorizationEndpointOffTheIssuerOriginOpensNoTab() {
        probes().run(new OAuthSignIn(URI.create("https://attacker.example.net"), AUTHORIZE,
                Optional.of(URI.create("https://attacker.example.net/register")), "scanner-client",
                Optional.of("MCP Scanner"), URI.create("http://127.0.0.1:4000/callback"), Set.of("read"),
                Optional.empty(), URI.create("https://mcp.example.test/mcp")));

        assertThat(http.sentUrls()).isEmpty();
        assertThat(browser.opened()).isEmpty();
    }

    @Test
    void aCodeAfterAColdBrowserStartIsStillCaughtByTheDefaultWait() {
        browser.replying(ScriptedBrowser.Reply.CODE_AFTER_COLD_START);

        probesWaiting(BrowserConsentWalk.CODE_WAIT).run(signIn());

        assertThat(observations.at(AUTHORIZE)).first()
                .satisfies(observation -> assertThat(observation.codeArrivedAfter()).isPresent());
    }

    @Test
    void aCodeTooLateToRuleOutAnApprovalClickTriesNoFreshNameAndIsLoggedAsNotCounted() {
        browser.replying(ScriptedBrowser.Reply.CODE);

        new BrowserConsentProbes(endpoint -> new ProbeClientRegistrar(http.oauth(), endpoint),
                new BrowserConsentWalk(listeners, browser, new SteppingClock(Duration.ofSeconds(3)), SHORT_WAIT,
                        observations), log).run(signIn());

        assertThat(observations.at(AUTHORIZE)).singleElement().satisfies(observation -> {
            assertThat(observation.codeArrivedAfter()).contains(Duration.ofSeconds(3));
            assertThat(observation.codeWithoutInteraction()).isFalse();
        });
        assertThat(messages()).anyMatch(message -> message.contains("after 3000 ms")
                && message.contains("too late to rule out an approval click"));
    }

    @Test
    void aSignInWhoseRegisteredNameIsUnknownSkipsTheSameNameProbeAndTriesAFreshName() {
        browser.replying(ScriptedBrowser.Reply.CODE);

        probes().run(signInNamed(Optional.empty()));

        assertThat(observations.at(AUTHORIZE)).singleElement()
                .satisfies(observation -> assertThat(observation.probe()).isEqualTo(SignedInProbe.FRESH_NAME));
        assertThat(messages()).anyMatch(message -> message.contains("SAME_NAME not run")
                && message.contains("registered name is unknown"));
    }

    @Test
    void theSameNameProbeRegistersTheNameTheServerHoldsForTheScannerClient() {
        probes().run(signInNamed(Optional.of("Name the server registered")));

        assertThat(registeredNames()).containsExactly("Name the server registered");
    }

    @Test
    void aCallbackCarryingAnotherStateIsNoCode() {
        browser.replying(ScriptedBrowser.Reply.CODE_WITH_OTHER_STATE);

        probes().run(signIn());

        assertThat(observations.at(AUTHORIZE)).singleElement()
                .satisfies(observation -> assertThat(observation.codeArrivedAfter()).isEmpty());
        assertThat(browser.opened()).hasSize(1);
    }

    @Test
    void aRefusedAuthorizationIsNoCode() {
        browser.replying(ScriptedBrowser.Reply.ACCESS_DENIED);

        probes().run(signIn());

        assertThat(observations.at(AUTHORIZE)).singleElement()
                .satisfies(observation -> assertThat(observation.codeArrivedAfter()).isEmpty());
    }

    @Test
    void opensACodeRequestWithPkceStateResourceAndTheGrantedScopesWithoutForcingALogin() {
        probes().run(signIn());

        URI opened = browser.opened().get(0);
        assertThat(opened.toString()).startsWith(AUTHORIZE + "?");
        assertThat(ScriptedBrowser.parameter(opened, "response_type")).isEqualTo("code");
        assertThat(ScriptedBrowser.parameter(opened, "client_id")).isEqualTo("probe-1");
        assertThat(ScriptedBrowser.parameter(opened, "code_challenge_method")).isEqualTo("S256");
        assertThat(ScriptedBrowser.parameter(opened, "code_challenge")).isNotBlank();
        assertThat(ScriptedBrowser.parameter(opened, "state")).isNotBlank();
        assertThat(ScriptedBrowser.parameter(opened, "resource")).isEqualTo("https://mcp.example.test/mcp");
        assertThat(ScriptedBrowser.parameter(opened, "scope")).isIn("read write", "write read");
        assertThat(ScriptedBrowser.parameter(opened, "prompt")).isNull();
    }

    @Test
    void registersTheProbeClientOnItsOwnLoopbackListenerUnderAnotherHostThanTheScannersCallback() throws Exception {
        probes().run(signIn());

        URI redirect = URI.create(ScriptedBrowser.parameter(browser.opened().get(0), "redirect_uri"));
        JsonNode body = McpObjectMapper.INSTANCE.readTree(registrations().get(0).bodyToString());
        assertThat(redirect.getScheme()).isEqualTo("http");
        assertThat(redirect.getHost()).isEqualTo("[::1]");
        assertThat(redirect.getPort()).isNotEqualTo(4000);
        assertThat(body.path("redirect_uris")).extracting(JsonNode::asText).containsExactly(redirect.toString());
        assertThat(observations.at(AUTHORIZE).get(0).redirectUri()).isEqualTo(redirect);
    }

    @Test
    void aScannerCallbackOnLocalhostPutsTheProbesOnTheLoopbackAddress() {
        browser.replying(ScriptedBrowser.Reply.CODE);

        probes().run(signInWithCallback(URI.create("http://LocalHost:4000/callback")));

        assertThat(browser.opened()).extracting(uri -> URI.create(ScriptedBrowser.parameter(uri, "redirect_uri")).getHost())
                .containsExactly("127.0.0.1", "127.0.0.1");
    }

    @Test
    void bothProbesRedirectToAnotherHostThanTheScannersCallbackSoARedirectHostShortcutCannotFireThem() {
        browser.replying(ScriptedBrowser.Reply.CODE);

        probes().run(signIn());

        assertThat(observations.at(AUTHORIZE)).extracting(observation -> observation.redirectUri().getHost())
                .containsExactly("[::1]", "[::1]");
    }

    @Test
    void eachProbeListensOnAFreshPath() {
        browser.replying(ScriptedBrowser.Reply.CODE);

        probes().run(signIn());

        assertThat(browser.opened()).extracting(uri -> ScriptedBrowser.parameter(uri, "redirect_uri"))
                .doesNotHaveDuplicates().hasSize(2);
    }

    @Test
    void theListenerIsClosedAfterTheWaitSoALaterApprovalReachesNoOne() {
        probes().run(signIn());

        URI lateApproval = URI.create(ScriptedBrowser.parameter(browser.opened().get(0), "redirect_uri")
                + "?code=late&state=" + ScriptedBrowser.parameter(browser.opened().get(0), "state"));
        assertThatThrownBy(() -> ScriptedBrowser.callbackStatus(lateApproval)).isInstanceOf(IOException.class);
    }

    @Test
    void deletesEveryProbeClientAndLogsTheCleanup() {
        browser.replying(ScriptedBrowser.Reply.CODE);

        probes().run(signIn());

        assertThat(http.sentTo(REGISTER + "/probe-1")).hasSize(1);
        assertThat(http.sentTo(REGISTER + "/probe-2")).hasSize(1);
        assertThat(messages()).anyMatch(message -> message.contains("deleted 2 of 2"));
    }

    @Test
    void deletesTheProbeClientWhenTheBrowserCannotBeOpened() {
        browser.replying(ScriptedBrowser.Reply.LAUNCH_FAILS);

        probes().run(signIn());

        assertThat(http.sentTo(REGISTER + "/probe-1")).hasSize(1);
        assertThat(observations.at(AUTHORIZE)).isEmpty();
        assertThat(messages()).anyMatch(message -> message.contains("no desktop"))
                .anyMatch(message -> message.contains("deleted 1 of 1"));
    }

    @Test
    void anUnloadDuringTheWaitTriesNoFurtherProbeButStillDeletesTheClientUninterrupted() {
        browser.replying(ScriptedBrowser.Reply.UNLOAD);
        List<Boolean> deletedWhileInterrupted = new java.util.concurrent.CopyOnWriteArrayList<>();
        http.on("DELETE", REGISTER + "/probe-1", request -> {
            deletedWhileInterrupted.add(Thread.currentThread().isInterrupted());
            return status(204);
        });

        probes().run(signIn());
        boolean stillInterrupted = Thread.interrupted();

        assertThat(browser.opened()).hasSize(1);
        assertThat(deletedWhileInterrupted).containsExactly(false);
        assertThat(stillInterrupted).isTrue();
        assertThat(messages()).anyMatch(message -> message.contains("deleted 1 of 1"))
                .anyMatch(message -> message.contains("stopped: the extension is unloading"))
                .noneMatch(message -> message.contains("consent asked"));
    }

    @Test
    void anUnloadDuringRegistrationOpensNoTabButStillDeletesTheClient() {
        http.on("POST", REGISTER, request -> {
            Thread.currentThread().interrupt();
            return registered("probe-1");
        });

        probes().run(signIn());
        boolean stillInterrupted = Thread.interrupted();

        assertThat(browser.opened()).isEmpty();
        assertThat(observations.at(AUTHORIZE)).isEmpty();
        assertThat(stillInterrupted).isTrue();
        assertThat(messages()).anyMatch(message -> message.contains("deleted 1 of 1"))
                .anyMatch(message -> message.contains("stopped: the extension is unloading"));
    }

    @Test
    void logsNothingSecret() {
        browser.replying(ScriptedBrowser.Reply.CODE);

        probes().run(signIn());

        assertThat(messages()).noneMatch(message -> message.contains(REGISTRATION_TOKEN)
                || message.contains(ScriptedBrowser.CODE) || message.contains("state="));
    }

    @Test
    void withoutARegistrationEndpointNothingIsSentAndNoBrowserOpens() {
        probes().run(signInRegisteringAt(Optional.empty()));

        assertThat(http.sent()).isEmpty();
        assertThat(browser.opened()).isEmpty();
        assertThat(messages()).anyMatch(message -> message.contains("registration endpoint"));
    }

    @Test
    void aRefusedRegistrationOpensNoBrowser() {
        http.on("POST", REGISTER, status(400));

        probes().run(signIn());

        assertThat(browser.opened()).isEmpty();
        assertThat(observations.at(AUTHORIZE)).isEmpty();
        assertThat(messages()).anyMatch(message -> message.contains("not registered"));
    }

    private BrowserConsentProbes probes() {
        return probesWaiting(SHORT_WAIT);
    }

    private BrowserConsentProbes probesWaiting(Duration codeWait) {
        return new BrowserConsentProbes(endpoint -> new ProbeClientRegistrar(http.oauth(), endpoint),
                new BrowserConsentWalk(listeners, browser, new SteppingClock(STEP), codeWait, observations), log);
    }

    private List<HttpRequest> registrations() {
        return http.sentTo(REGISTER);
    }

    private List<String> registeredNames() {
        return registrations().stream()
                .map(request -> readJson(request.bodyToString()).path("client_name").asText())
                .toList();
    }

    private List<String> messages() {
        return log.snapshot().stream().map(McpEventLog.LogEntry::message).toList();
    }

    private static JsonNode readJson(String body) {
        try {
            return McpObjectMapper.INSTANCE.readTree(body);
        } catch (IOException failure) {
            throw new IllegalStateException(failure);
        }
    }

    private static String registered(String clientId) {
        return json(201, "{\"client_id\":\"" + clientId + "\",\"registration_client_uri\":\"" + REGISTER + "/"
                + clientId + "\",\"registration_access_token\":\"" + REGISTRATION_TOKEN + "\"}");
    }

    static OAuthSignIn signIn() {
        return signInRegisteringAt(Optional.of(URI.create(REGISTER)));
    }

    private static OAuthSignIn signInRegisteringAt(Optional<URI> registrationEndpoint) {
        return signIn(registrationEndpoint, URI.create("http://127.0.0.1:4000/callback"), Optional.of("MCP Scanner"));
    }

    private static OAuthSignIn signInWithCallback(URI scannerCallback) {
        return signIn(Optional.of(URI.create(REGISTER)), scannerCallback, Optional.of("MCP Scanner"));
    }

    private static OAuthSignIn signInNamed(Optional<String> registeredName) {
        return signIn(Optional.of(URI.create(REGISTER)), URI.create("http://127.0.0.1:4000/callback"), registeredName);
    }

    private static OAuthSignIn signIn(Optional<URI> registrationEndpoint, URI scannerCallback,
                                      Optional<String> registeredName) {
        return new OAuthSignIn(URI.create("https://auth.example.test"), AUTHORIZE, registrationEndpoint,
                "scanner-client", registeredName, scannerCallback,
                Set.of("read", "write"), Optional.empty(), URI.create("https://mcp.example.test/mcp"));
    }

    private static final class SteppingClock extends Clock {

        private final Duration step;
        private Instant now = Instant.parse("2026-11-18T10:00:00Z");

        private SteppingClock(Duration step) {
            this.step = step;
        }

        @Override
        public synchronized Instant instant() {
            Instant current = now;
            now = now.plus(step);
            return current;
        }

        @Override
        public ZoneId getZone() {
            return ZoneOffset.UTC;
        }

        @Override
        public Clock withZone(ZoneId zone) {
            return this;
        }
    }
}
