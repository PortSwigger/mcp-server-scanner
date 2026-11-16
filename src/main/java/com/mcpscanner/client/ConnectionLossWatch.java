package com.mcpscanner.client;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayDeque;
import java.util.Deque;
import java.util.concurrent.Executor;
import java.util.function.Supplier;

public final class ConnectionLossWatch {

    public static final int DEFAULT_THRESHOLD = 5;
    public static final Duration DEFAULT_WINDOW = Duration.ofSeconds(60);
    public static final int DEFAULT_CONFIRMING_PINGS = 3;
    public static final Duration DEFAULT_PING_SPACING = Duration.ofSeconds(5);

    @FunctionalInterface
    public interface Pause {
        void between() throws InterruptedException;

        static Pause of(Duration spacing) {
            return () -> Thread.sleep(spacing.toMillis());
        }
    }

    private final int threshold;
    private final Duration window;
    private final Clock clock;
    private final Supplier<PingOutcome> ping;
    private final int confirmingPings;
    private final Pause pause;
    private final Executor confirmations;
    private final Runnable onLost;
    private final Deque<Instant> failures = new ArrayDeque<>();
    private boolean confirming;

    public ConnectionLossWatch(int threshold, Duration window, Clock clock, Supplier<PingOutcome> ping,
                               int confirmingPings, Pause pause, Executor confirmations, Runnable onLost) {
        this.threshold = threshold;
        this.window = window;
        this.clock = clock;
        this.ping = ping;
        this.confirmingPings = confirmingPings;
        this.pause = pause;
        this.confirmations = confirmations;
        this.onLost = onLost;
    }

    public static ConnectionLossWatch disabled() {
        return new ConnectionLossWatch(Integer.MAX_VALUE, DEFAULT_WINDOW, Clock.systemUTC(),
                () -> PingOutcome.ANSWERED, 1, () -> { }, Runnable::run, () -> { });
    }

    public void failed() {
        if (recordedEnoughFailures()) {
            confirmations.execute(this::confirm);
        }
    }

    private synchronized boolean recordedEnoughFailures() {
        Instant now = clock.instant();
        failures.addLast(now);
        while (failures.peekFirst().isBefore(now.minus(window))) {
            failures.removeFirst();
        }
        if (failures.size() < threshold || confirming) {
            return false;
        }
        confirming = true;
        return true;
    }

    private void confirm() {
        try {
            boolean gone = persistentlyGone();
            forgetFailures();
            if (gone) {
                onLost.run();
            }
        } catch (InterruptedException interrupted) {
            Thread.currentThread().interrupt();
        } finally {
            finishConfirming();
        }
    }

    private boolean persistentlyGone() throws InterruptedException {
        for (int attempt = 1; attempt <= confirmingPings; attempt++) {
            PingOutcome outcome = ping.get();
            if (outcome.provesLoss()) {
                return true;
            }
            if (!outcome.suggestsLoss()) {
                return false;
            }
            if (attempt < confirmingPings) {
                pause.between();
            }
        }
        return true;
    }

    private synchronized void forgetFailures() {
        failures.clear();
    }

    private synchronized void finishConfirming() {
        confirming = false;
    }
}
