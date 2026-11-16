package com.mcpscanner.client;

import org.junit.jupiter.api.Test;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.ArrayDeque;
import java.util.Deque;
import java.util.List;
import java.util.concurrent.atomic.AtomicInteger;

import static org.assertj.core.api.Assertions.assertThat;

class ConnectionLossWatchTest {

    private static final int THRESHOLD = 3;
    private static final Duration WINDOW = Duration.ofSeconds(60);

    private static final int CONFIRMING_PINGS = 3;

    private final AdjustableClock clock = new AdjustableClock();
    private final Deque<PingOutcome> pingOutcomes = new ArrayDeque<>();
    private final AtomicInteger probes = new AtomicInteger();
    private final AtomicInteger pauses = new AtomicInteger();
    private final AtomicInteger losses = new AtomicInteger();
    private final ConnectionLossWatch watch = new ConnectionLossWatch(THRESHOLD, WINDOW, clock, this::ping,
            CONFIRMING_PINGS, pauses::incrementAndGet, Runnable::run, losses::incrementAndGet);

    private PingOutcome ping() {
        probes.incrementAndGet();
        return pingOutcomes.isEmpty() ? PingOutcome.ANSWERED : pingOutcomes.removeFirst();
    }

    private void pingsReturn(PingOutcome... outcomes) {
        pingOutcomes.addAll(List.of(outcomes));
    }

    @Test
    void failuresBelowTheThresholdNeverProbeTheLiveSession() {
        failTimes(THRESHOLD - 1);

        assertThat(probes).hasValue(0);
        assertThat(losses).hasValue(0);
    }

    @Test
    void aRefusedSessionIsALossOnTheFirstPing() {
        pingsReturn(PingOutcome.SESSION_REFUSED);

        failTimes(THRESHOLD);

        assertThat(probes).hasValue(1);
        assertThat(losses).hasValue(1);
    }

    @Test
    void anUnreachableServerThatStaysUnreachableIsALoss() {
        pingsReturn(PingOutcome.UNREACHABLE, PingOutcome.TIMED_OUT, PingOutcome.UNREACHABLE);

        failTimes(THRESHOLD);

        assertThat(probes).hasValue(CONFIRMING_PINGS);
        assertThat(losses).hasValue(1);
    }

    @Test
    void aTransientOutageThatRecoversBetweenPingsIsNotALoss() {
        pingsReturn(PingOutcome.UNREACHABLE, PingOutcome.UNREACHABLE, PingOutcome.ANSWERED);

        failTimes(THRESHOLD);

        assertThat(probes).hasValue(CONFIRMING_PINGS);
        assertThat(losses).hasValue(0);
    }

    @Test
    void aBriefOutageThatRecoversOnTheSecondPingStopsPinging() {
        pingsReturn(PingOutcome.UNREACHABLE, PingOutcome.ANSWERED);

        failTimes(THRESHOLD);

        assertThat(probes).hasValue(2);
        assertThat(pauses).hasValue(1);
        assertThat(losses).hasValue(0);
    }

    @Test
    void aBackloggedPingThatTimesOnceThenAnswersIsNotALoss() {
        pingsReturn(PingOutcome.TIMED_OUT, PingOutcome.ANSWERED);

        failTimes(THRESHOLD);

        assertThat(losses).hasValue(0);
    }

    @Test
    void aGarbagePingReplyIsNotALoss() {
        pingsReturn(PingOutcome.INCONCLUSIVE);

        failTimes(THRESHOLD);

        assertThat(probes).hasValue(1);
        assertThat(losses).hasValue(0);
    }

    @Test
    void anAnsweringSessionIsNotALoss() {
        failTimes(THRESHOLD);

        assertThat(probes).hasValue(1);
        assertThat(losses).hasValue(0);
    }

    @Test
    void failuresSpacedApartWithinTheWindowStillAddUp() {
        pingsReturn(PingOutcome.SESSION_REFUSED);

        for (int i = 0; i < THRESHOLD; i++) {
            watch.failed();
            clock.advance(Duration.ofSeconds(5));
        }

        assertThat(losses).hasValue(1);
    }

    @Test
    void failuresSpreadOverMoreThanTheWindowDoNotAddUp() {
        for (int i = 0; i < THRESHOLD * 2; i++) {
            watch.failed();
            clock.advance(WINDOW.plusSeconds(1));
        }

        assertThat(probes).hasValue(0);
    }

    @Test
    void anAnsweringSessionStartsTheCountAgain() {
        failTimes(THRESHOLD);
        failTimes(THRESHOLD - 1);

        assertThat(probes).hasValue(1);
    }

    @Test
    void aDisabledWatchNeverReportsALoss() {
        ConnectionLossWatch disabled = ConnectionLossWatch.disabled();

        for (int i = 0; i < 1000; i++) {
            disabled.failed();
        }
    }

    private void failTimes(int count) {
        for (int i = 0; i < count; i++) {
            watch.failed();
        }
    }

    private static final class AdjustableClock extends Clock {
        private Instant now = Instant.parse("2026-11-13T00:00:00Z");

        void advance(Duration by) {
            now = now.plus(by);
        }

        @Override
        public Instant instant() {
            return now;
        }

        @Override
        public java.time.ZoneId getZone() {
            return ZoneOffset.UTC;
        }

        @Override
        public Clock withZone(java.time.ZoneId zone) {
            return this;
        }
    }
}
