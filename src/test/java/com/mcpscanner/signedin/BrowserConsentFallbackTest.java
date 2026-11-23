package com.mcpscanner.signedin;

import burp.api.montoya.logging.Logging;
import com.mcpscanner.auth.oauth.ActiveCallbackListeners;
import com.mcpscanner.checks.shared.oauth.ProbeClientRegistrar;
import com.mcpscanner.checks.shared.oauth.ScriptedHttp;
import com.mcpscanner.config.ExtensionConfigStore;
import com.mcpscanner.config.SignedInConsentSetting;
import com.mcpscanner.logging.McpEventLog;
import com.mcpscanner.testutil.InMemoryPersistedObject;
import com.mcpscanner.testutil.InMemoryPreferences;
import com.mcpscanner.testutil.MontoyaTestFactory;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.time.Clock;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.Executor;

import static com.mcpscanner.checks.shared.oauth.ScriptedHttp.status;
import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;

class BrowserConsentFallbackTest {

    private final SignedInConsentSetting setting = new SignedInConsentSetting(
            new ExtensionConfigStore(InMemoryPersistedObject.create(), new InMemoryPreferences(), mock(Logging.class)));
    private final ScriptedHttp http = new ScriptedHttp();
    private final ScriptedBrowser browser = new ScriptedBrowser();
    private final ActiveCallbackListeners listeners = new ActiveCallbackListeners();
    private final List<Runnable> queued = new ArrayList<>();
    private final Executor recordingWorker = queued::add;

    @BeforeEach
    void setUp() {
        MontoyaTestFactory.install();
        http.on("POST", "https://auth.example.test/register", status(400));
    }

    @AfterEach
    void tearDown() {
        listeners.closeAll();
    }

    @Test
    void withTheSettingOffNothingIsSentAndNoBrowserOpens() {
        fallback(recordingWorker).signedIn(BrowserConsentProbesTest.signIn());

        queued.forEach(Runnable::run);
        assertThat(queued).isEmpty();
        assertThat(http.sent()).isEmpty();
        assertThat(browser.opened()).isEmpty();
    }

    @Test
    void withTheSettingOnTheProbesRunOnTheWorkerNotTheSignInThread() {
        setting.optIn(true);

        fallback(recordingWorker).signedIn(BrowserConsentProbesTest.signIn());

        assertThat(http.sent()).isEmpty();
        queued.forEach(Runnable::run);
        assertThat(http.sentTo("https://auth.example.test/register")).hasSize(1);
    }

    private BrowserConsentFallback fallback(Executor worker) {
        BrowserConsentProbes probes = new BrowserConsentProbes(
                endpoint -> new ProbeClientRegistrar(http.oauth(), endpoint),
                new BrowserConsentWalk(listeners, browser, Clock.systemUTC(), Duration.ofMillis(50),
                        new BrowserConsentObservations()),
                McpEventLog.noop());
        return new BrowserConsentFallback(setting, worker, probes);
    }
}
