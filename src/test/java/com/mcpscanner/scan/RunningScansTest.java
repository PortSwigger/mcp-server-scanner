package com.mcpscanner.scan;

import com.mcpscanner.logging.McpEventLog;
import org.junit.jupiter.api.Test;

import burp.api.montoya.scanner.audit.Audit;

import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

class RunningScansTest {

    private final McpEventLog eventLog = new McpEventLog(null);
    private final ManualEndPoller poller = new ManualEndPoller();
    private final AtomicBoolean burpTasksPaused = new AtomicBoolean();
    private final RunningScans runningScans = new RunningScans(eventLog, poller, burpTasksPaused::get);
    private final Audit audit = mock(Audit.class);
    private final AtomicInteger ends = new AtomicInteger();

    @Test
    void activityCountsBurpAuditRequestsApartFromEngineProbesAndSumsIssues() {
        runningScans.track(FakeRun.burpAudit(3, 1));
        runningScans.track(FakeRun.engineRun(4, 2));

        assertThat(runningScans.activity()).isEqualTo(new ScanActivity(1, 3, 1, 4, 3));
    }

    @Test
    void finishedScansAreDroppedFromActivity() {
        FakeRun engineRun = runningScans.track(FakeRun.engineRun(4, 2));
        runningScans.track(FakeRun.burpAudit(3, 1));

        engineRun.finish();

        assertThat(runningScans.activity()).isEqualTo(ScanActivity.burpAudit(3, 1));
    }

    @Test
    void cancellingAllCancelsEveryScanAndForgetsThem() {
        FakeRun burpAudit = runningScans.track(FakeRun.burpAudit(0, 0));
        FakeRun engineRun = runningScans.track(FakeRun.engineRun(0, 0));

        runningScans.cancelAll();

        assertThat(burpAudit.cancelled()).isTrue();
        assertThat(engineRun.cancelled()).isTrue();
        assertThat(runningScans.activity().isIdle()).isTrue();
    }

    @Test
    void aScanThatFailsToCancelIsLoggedAndTheOthersAreStillCancelled() {
        runningScans.track(FakeRun.burpAudit(0, 0).failingToCancel());
        FakeRun engineRun = runningScans.track(FakeRun.engineRun(0, 0));

        runningScans.cancelAll();

        assertThat(engineRun.cancelled()).isTrue();
        assertThat(eventLog.snapshot()).anySatisfy(entry ->
                assertThat(entry.message()).isEqualTo("Scan cancel failed: IllegalStateException"));
    }

    @Test
    void clearingForgetsBurpAuditsWithoutCancellingThemBecauseTheDashboardStillOwnsThem() {
        FakeRun burpAudit = runningScans.track(FakeRun.burpAudit(0, 0));

        runningScans.clear();

        assertThat(burpAudit.cancelled()).isFalse();
        assertThat(runningScans.activity().isIdle()).isTrue();
    }

    @Test
    void clearingCancelsEngineRunsBecauseNothingElseCouldStopThem() {
        FakeRun engineRun = runningScans.track(FakeRun.engineRun(0, 0));

        runningScans.clear();

        assertThat(engineRun.cancelled()).isTrue();
        assertThat(runningScans.activity().isIdle()).isTrue();
    }

    @Test
    void scansClearedAwayAreNotCancelledAgainLater() {
        FakeRun burpAudit = runningScans.track(FakeRun.burpAudit(0, 0));
        runningScans.clear();

        runningScans.cancelAll();

        assertThat(burpAudit.cancelled()).isFalse();
    }

    @Test
    void failAllFailsEngineScansWithTheReasonAndLeavesBurpAuditsRunning() {
        FakeRun engineRun = runningScans.track(FakeRun.engineRun(1, 0));
        FakeRun burpAudit = runningScans.track(FakeRun.burpAudit(1, 0));

        runningScans.failAll("Connection lost");

        assertThat(engineRun.failure()).isEqualTo("Connection lost");
        assertThat(burpAudit.failure()).isNull();
        assertThat(burpAudit.cancelled()).isFalse();
    }

    @Test
    void scansFailedAreNotCancelledAgainByTheDisconnectThatFollows() {
        FakeRun engineRun = runningScans.track(FakeRun.engineRun(1, 0));
        runningScans.failAll("Connection lost");

        runningScans.clear();

        assertThat(engineRun.cancelled()).isFalse();
    }

    @Test
    void anAuditClearedAwayAtDisconnectStillEndsWhenBurpFinishesIt() {
        BurpAuditRun run = runningScans.track(new BurpAuditRun(audit));
        run.whenEnded(ends::incrementAndGet);
        when(audit.statusMessage()).thenReturn("Auditing");
        runningScans.clear();

        poller.runPending();
        assertThat(ends).hasValue(0);
        when(audit.statusMessage()).thenReturn("Finished");
        poller.runPending();

        assertThat(ends).hasValue(1);
        assertThat(poller.pending()).isZero();
    }

    @Test
    void anAuditDroppedByAConnectionFailureStillEndsWhenBurpFinishesIt() {
        BurpAuditRun run = runningScans.track(new BurpAuditRun(audit));
        run.whenEnded(ends::incrementAndGet);
        when(audit.statusMessage()).thenReturn("Finished");
        runningScans.failAll("Connection lost");

        poller.runPending();

        assertThat(ends).hasValue(1);
    }

    @Test
    void shuttingDownStopsThePollerAndForgetsDetachedAudits() {
        runningScans.track(new BurpAuditRun(audit));
        runningScans.clear();

        runningScans.shutdown();
        poller.runPending();

        assertThat(poller.isShutDown()).isTrue();
        assertThat(poller.pending()).isZero();
        verify(audit, never()).statusMessage();
    }

    @Test
    void anAuditBurpNoLongerKnowsEndsInsteadOfBeingPolledForever() {
        BurpAuditRun run = runningScans.track(new BurpAuditRun(audit));
        run.whenEnded(ends::incrementAndGet);
        when(audit.statusMessage()).thenThrow(new IllegalStateException("task deleted"));
        runningScans.clear();

        for (int poll = 1; poll < RunningScans.CONSECUTIVE_FAILURES_BEFORE_ENDED; poll++) {
            poller.runPending();
        }
        assertThat(ends).hasValue(0);
        poller.runPending();

        assertThat(ends).hasValue(1);
        assertThat(poller.pending()).isZero();
    }

    @Test
    void aSingleTransientFailureIsRetriedAndTheAuditIsStillWatched() {
        BurpAuditRun run = runningScans.track(new BurpAuditRun(audit));
        run.whenEnded(ends::incrementAndGet);
        when(audit.statusMessage()).thenThrow(new IllegalStateException("transient")).thenReturn("Finished");
        runningScans.clear();

        poller.runPending();
        assertThat(ends).hasValue(0);
        assertThat(poller.pending()).isEqualTo(1);
        poller.runPending();

        assertThat(ends).hasValue(1);
    }

    @Test
    void failuresSeparatedByASuccessfulPollNeverAddUpToEnded() {
        BurpAuditRun run = runningScans.track(new BurpAuditRun(audit));
        run.whenEnded(ends::incrementAndGet);
        when(audit.statusMessage()).thenThrow(new IllegalStateException("transient"))
                .thenThrow(new IllegalStateException("transient")).thenReturn("Auditing")
                .thenThrow(new IllegalStateException("transient")).thenThrow(new IllegalStateException("transient"))
                .thenReturn("Auditing");
        runningScans.clear();

        for (int poll = 0; poll < 6; poll++) {
            poller.runPending();
        }

        assertThat(ends).hasValue(0);
        assertThat(poller.pending()).isEqualTo(1);
    }

    @Test
    void anAuditDroppedAfterShutdownIsNotWatchedBecauseNothingCouldPollIt() {
        runningScans.track(new BurpAuditRun(audit));
        runningScans.shutdown();
        int requestsBefore = poller.pollRequests();

        runningScans.clear();

        assertThat(poller.pollRequests()).isEqualTo(requestsBefore);
    }

    @Test
    void burpAuditsCannotBeAskedForAnOutcomeBecauseOnlyEngineRunsHaveOne() {
        assertThat(OutcomeReportingScan.class.isAssignableFrom(BurpAuditRun.class)).isFalse();
        assertThat(OutcomeReportingScan.class.isAssignableFrom(EngineRun.class)).isTrue();
    }

    @Test
    void anAuditThatNeverReportsFinishedIsGivenUpOnAtTheCeiling() {
        BurpAuditRun run = runningScans.track(new BurpAuditRun(audit));
        run.whenEnded(ends::incrementAndGet);
        when(audit.statusMessage()).thenReturn("Auditing");
        runningScans.clear();

        for (int poll = 1; poll < RunningScans.MAX_POLLS_PER_DETACHED_SCAN; poll++) {
            poller.runPending();
        }
        assertThat(ends).hasValue(0);
        poller.runPending();

        assertThat(ends).hasValue(1);
        assertThat(poller.pending()).isZero();
    }

    @Test
    void pollsWhileBurpTasksArePausedDoNotCountTowardsTheCeiling() {
        BurpAuditRun run = runningScans.track(new BurpAuditRun(audit));
        run.whenEnded(ends::incrementAndGet);
        when(audit.statusMessage()).thenReturn("Auditing");
        runningScans.clear();
        burpTasksPaused.set(true);

        for (int poll = 0; poll <= RunningScans.MAX_POLLS_PER_DETACHED_SCAN; poll++) {
            poller.runPending();
        }

        assertThat(ends).hasValue(0);
        assertThat(poller.pending()).isOne();
    }

    @Test
    void pollsCountTowardsTheCeilingAgainOnceBurpTasksResume() {
        BurpAuditRun run = runningScans.track(new BurpAuditRun(audit));
        run.whenEnded(ends::incrementAndGet);
        when(audit.statusMessage()).thenReturn("Auditing");
        runningScans.clear();
        burpTasksPaused.set(true);
        poller.runPending();
        burpTasksPaused.set(false);

        for (int poll = 1; poll < RunningScans.MAX_POLLS_PER_DETACHED_SCAN; poll++) {
            poller.runPending();
        }
        assertThat(ends).hasValue(0);
        poller.runPending();

        assertThat(ends).hasValue(1);
    }

    @Test
    void aPauseStateBurpCannotReportCountsThePollSoTheAuditIsStillWatched() {
        RunningScans failingPauseState = new RunningScans(eventLog, poller, () -> {
            throw new IllegalStateException("unloading");
        });
        failingPauseState.track(new BurpAuditRun(audit));
        when(audit.statusMessage()).thenReturn("Auditing");
        failingPauseState.clear();

        poller.runPending();

        assertThat(poller.pending()).isOne();
    }

    @Test
    void pollingDoesNotHoldTheRunningScansMonitorWhileCallingBurp() throws Exception {
        runningScans.track(new BurpAuditRun(audit));
        runningScans.clear();
        AtomicBoolean monitorHeld = new AtomicBoolean(true);
        when(audit.statusMessage()).thenAnswer(call -> {
            monitorHeld.set(Thread.holdsLock(runningScans));
            return "Auditing";
        });

        poller.runPending();

        assertThat(monitorHeld).isFalse();
    }

    @Test
    void nothingIsPolledWhileNoAuditHasBeenDropped() {
        runningScans.track(FakeRun.engineRun(0, 0));

        runningScans.clear();

        assertThat(poller.pending()).isZero();
    }

    private static final class FakeRun implements RunningScan {

        private final ScanActivity activity;
        private final boolean outlivesConnection;
        private boolean failsToCancel;
        private boolean cancelled;
        private boolean finished;
        private String failure;

        private FakeRun(ScanActivity activity, boolean outlivesConnection) {
            this.activity = activity;
            this.outlivesConnection = outlivesConnection;
        }

        static FakeRun burpAudit(int requests, int issues) {
            return new FakeRun(ScanActivity.burpAudit(requests, issues), true);
        }

        static FakeRun engineRun(int probesRun, int issues) {
            return new FakeRun(ScanActivity.mcpOnlyScan(probesRun, issues), false);
        }

        FakeRun failingToCancel() {
            failsToCancel = true;
            return this;
        }

        void finish() {
            finished = true;
        }

        boolean cancelled() {
            return cancelled;
        }

        String failure() {
            return failure;
        }

        @Override
        public void failWith(String reason) {
            failure = reason;
        }

        @Override
        public ScanActivity activity() {
            return activity;
        }

        @Override
        public boolean isFinished() {
            return finished;
        }

        @Override
        public boolean outlivesConnection() {
            return outlivesConnection;
        }

        @Override
        public void cancel() {
            if (failsToCancel) {
                throw new IllegalStateException("cancel failed");
            }
            cancelled = true;
        }

        @Override
        public void whenEnded(Runnable action) {
        }
    }
}
