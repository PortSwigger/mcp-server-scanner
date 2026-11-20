package com.mcpscanner.cvetargets.burp;

import com.mcpscanner.automation.SendCanaryCommand;
import com.mcpscanner.automation.SendCanaryReport;
import com.mcpscanner.cvetargets.environment.Pause;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;

import java.time.Duration;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertTimeoutPreemptively;

@Tag("burp-canary")
class BurpIdleClosedConnectionCanaryTest {

    private static final Duration ANSWER_BUDGET = Duration.ofSeconds(30);
    private static final int CONCURRENT_SENDERS = 6;
    private static final Duration SCAN_QUEUE_WAIT = IdleClosingOrigin.IDLE_TIMEOUT.plusSeconds(1);

    private static HeadlessBurpSession burp;
    private static IdleClosingOrigin origin;
    private static IdleClosingOrigin queuedOrigin;

    @BeforeAll
    static void startBurpAndOrigin() {
        origin = IdleClosingOrigin.start();
        queuedOrigin = IdleClosingOrigin.start();
        burp = new HeadlessBurpLauncher(BurpSettings.fromSystemProperties(), Pause.sleeping())
                .start("idle-closed-connection-canary", origin.url(), () -> false);
    }

    @AfterAll
    static void stopBurpAndOrigin() {
        if (burp != null) {
            burp.close();
        }
        origin.close();
        queuedOrigin.close();
    }

    @Test
    void aSendAfterTheServerClosedTheIdleKeptAliveConnectionIsAnswered() {
        SendCanaryCommand oneSend = new SendCanaryCommand(origin.url(), 1, 1);
        burp.automation().sendCanary(oneSend);
        burp.automation().sendCanary(oneSend);
        int closedBefore = origin.idleClosed();
        waitForTheOriginToCloseIdleConnections();

        SendCanaryReport afterIdle = assertTimeoutPreemptively(ANSWER_BUDGET,
                () -> burp.automation().sendCanary(oneSend));

        assertThat(origin.idleClosed()).as("connections the origin closed while idle").isGreaterThan(closedBefore);
        assertThat(afterIdle.unanswered()).isZero();
    }

    @Test
    void concurrentSendsAfterTheServerClosedEveryIdleKeptAliveConnectionAreAllAnswered() {
        SendCanaryCommand concurrentSends = new SendCanaryCommand(origin.url(), CONCURRENT_SENDERS * 4,
                CONCURRENT_SENDERS);
        burp.automation().sendCanary(new SendCanaryCommand(origin.url(), 1, 1));
        burp.automation().sendCanary(concurrentSends);
        int closedBefore = origin.idleClosed();
        waitForTheOriginToCloseIdleConnections();

        SendCanaryReport afterIdle = assertTimeoutPreemptively(ANSWER_BUDGET,
                () -> burp.automation().sendCanary(concurrentSends));

        assertThat(origin.idleClosed() - closedBefore).as("kept-alive connections the origin closed while idle")
                .isGreaterThan(1);
        assertThat(afterIdle.unanswered()).isZero();
    }

    @Test
    void aReadQueuedPastTheServersKeepAliveAfterTakingAFreshConnectionIsAnswered() {
        SendCanaryCommand queuedSend = new SendCanaryCommand(queuedOrigin.url(), 1, 1,
                (int) SCAN_QUEUE_WAIT.toMillis());
        burp.automation().sendCanary(queuedSend);
        burp.automation().sendCanary(queuedSend);
        int closedBefore = queuedOrigin.idleClosed();

        SendCanaryReport queued = assertTimeoutPreemptively(ANSWER_BUDGET,
                () -> burp.automation().sendCanary(queuedSend));

        assertThat(queuedOrigin.idleClosed()).as("connections the origin closed while the send was queued")
                .isGreaterThan(closedBefore);
        assertThat(queued.unanswered()).isZero();
    }

    private static void waitForTheOriginToCloseIdleConnections() {
        Pause.sleeping().pause(IdleClosingOrigin.IDLE_TIMEOUT.multipliedBy(2));
    }
}
