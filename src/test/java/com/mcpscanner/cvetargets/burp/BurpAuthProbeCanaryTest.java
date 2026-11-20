package com.mcpscanner.cvetargets.burp;

import com.mcpscanner.automation.AuthProbeCommand;
import com.mcpscanner.automation.AuthProbeReport;
import com.mcpscanner.cvetargets.environment.Pause;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import java.time.Duration;

import static org.assertj.core.api.Assertions.assertThat;

@Tag("burp-canary")
class BurpAuthProbeCanaryTest {

    private static final Duration PROMPT_STREAM_CLASSIFICATION = Duration.ofSeconds(3);

    private static AuthProbeOrigin bearerChallenge;
    private static AuthProbeOrigin heldOpenEventStream;
    private static AuthProbeOrigin silent;
    private static HeadlessBurpSession burp;

    @BeforeAll
    static void startBurpAndOrigins() {
        bearerChallenge = AuthProbeOrigin.bearerChallenge();
        heldOpenEventStream = AuthProbeOrigin.heldOpenEventStream();
        silent = AuthProbeOrigin.silent();
        burp = new HeadlessBurpLauncher(BurpSettings.fromSystemProperties(), Pause.sleeping())
                .start("auth-probe-canary", bearerChallenge.url(), () -> false);
    }

    @AfterAll
    static void stopBurpAndOrigins() {
        if (burp != null) {
            burp.close();
        }
        bearerChallenge.close();
        heldOpenEventStream.close();
        silent.close();
    }

    @ParameterizedTest(name = "useBurpNetworking={0}")
    @ValueSource(booleans = {true, false})
    void aBearerChallengeWithNoMetadataNeedsCredentials(boolean useBurpNetworking) {
        AuthProbeReport report = probe("bearer-401", bearerChallenge, useBurpNetworking);

        assertThat(report.requirement()).as(report.detail()).isEqualTo("CredentialsRequired");
    }

    @ParameterizedTest(name = "useBurpNetworking={0}")
    @ValueSource(booleans = {true, false})
    void aHeldOpenEventStreamNeedsNoAuthAndIsClassifiedPromptly(boolean useBurpNetworking) {
        AuthProbeReport report = probe("held-open-sse", heldOpenEventStream, useBurpNetworking);

        assertThat(report.requirement()).as(report.detail()).isEqualTo("NotRequired");
        assertThat(Duration.ofMillis(report.elapsedMillis())).as(report.detail())
                .isLessThan(PROMPT_STREAM_CLASSIFICATION);
    }

    @ParameterizedTest(name = "useBurpNetworking={0}")
    @ValueSource(booleans = {true, false})
    void aServerThatNeverAnswersIsUnsupported(boolean useBurpNetworking) {
        AuthProbeReport report = probe("silent", silent, useBurpNetworking);

        assertThat(report.requirement()).as(report.detail()).isEqualTo("Unsupported");
    }

    private static AuthProbeReport probe(String label, AuthProbeOrigin origin, boolean useBurpNetworking) {
        AuthProbeReport report = burp.automation().authProbe(new AuthProbeCommand(origin.url(), useBurpNetworking));
        System.out.printf("AUTH-PROBE | %-14s | %-5s | %-19s | %6d ms | %s%n", label,
                useBurpNetworking ? "burp" : "jdk", report.requirement(), report.elapsedMillis(), report.detail());
        return report;
    }
}
