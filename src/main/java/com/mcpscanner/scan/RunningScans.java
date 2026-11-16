package com.mcpscanner.scan;

import burp.api.montoya.burpsuite.BurpSuite;
import com.mcpscanner.logging.McpEventLog;

import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.function.BooleanSupplier;

public final class RunningScans {

    static final int MAX_POLLS_PER_DETACHED_SCAN = 17_280;
    static final int CONSECUTIVE_FAILURES_BEFORE_ENDED = 3;

    private static final class DetachedScan {
        private final RunningScan scan;
        private int polls;
        private int consecutiveFailures;

        DetachedScan(RunningScan scan) {
            this.scan = scan;
        }
    }

    private final McpEventLog eventLog;
    private final CopyOnWriteArrayList<RunningScan> scans = new CopyOnWriteArrayList<>();

    private final List<DetachedScan> detached = new ArrayList<>();
    private final EndPoller endPoller;
    private final BooleanSupplier burpTasksPaused;
    private boolean pollScheduled;
    private boolean shutDown;

    public RunningScans(McpEventLog eventLog, BurpSuite burpSuite) {
        this(eventLog, new DaemonEndPoller(), new BurpTaskExecution(burpSuite)::paused);
    }

    RunningScans(McpEventLog eventLog, EndPoller endPoller, BooleanSupplier burpTasksPaused) {
        this.eventLog = eventLog;
        this.endPoller = endPoller;
        this.burpTasksPaused = burpTasksPaused;
    }

    <T extends RunningScan> T track(T scan) {
        scans.add(scan);
        return scan;
    }

    ScanActivity activity() {
        scans.removeIf(RunningScan::isFinished);
        return scans.stream().map(RunningScan::activity).reduce(ScanActivity.idle(), ScanActivity::plus);
    }

    void cancelAll() {
        untrackAll().forEach(this::tryCancel);
    }

    void failAll(String reason) {
        List<RunningScan> untracked = untrackAll();
        untracked.stream().filter(scan -> !scan.outlivesConnection()).forEach(scan -> tryFail(scan, reason));
        detach(untracked);
    }

    void clear() {
        List<RunningScan> untracked = untrackAll();
        untracked.stream().filter(scan -> !scan.outlivesConnection()).forEach(this::tryCancel);
        detach(untracked);
    }

    private synchronized void detach(List<RunningScan> untracked) {
        if (shutDown) {
            return;
        }
        untracked.stream().filter(RunningScan::outlivesConnection).map(DetachedScan::new).forEach(detached::add);
        scheduleNextPoll();
    }

    void pollDetached() {
        List<DetachedScan> due = beginPoll();
        boolean counted = !burpTasksPaused();
        List<DetachedScan> ended = due.stream().filter(scan -> hasEnded(scan, counted)).toList();
        finishPoll(ended);
    }

    private synchronized List<DetachedScan> beginPoll() {
        pollScheduled = false;
        return List.copyOf(detached);
    }

    private synchronized void finishPoll(List<DetachedScan> ended) {
        detached.removeAll(ended);
        scheduleNextPoll();
    }

    synchronized void shutdown() {
        shutDown = true;
        detached.clear();
        pollScheduled = false;
        endPoller.shutdown();
    }

    private boolean burpTasksPaused() {
        try {
            return burpTasksPaused.getAsBoolean();
        } catch (RuntimeException e) {
            eventLog.warn("Burp task state check failed: " + e.getClass().getSimpleName());
            return false;
        }
    }

    private boolean hasEnded(DetachedScan detachedScan, boolean counted) {
        if (counted) {
            detachedScan.polls++;
        }
        if (detachedScan.polls >= MAX_POLLS_PER_DETACHED_SCAN) {
            eventLog.warn("Scan end check gave up after " + detachedScan.polls + " polls");
            return stopWatching(detachedScan);
        }
        try {
            boolean ended = detachedScan.scan.pollEnded();
            detachedScan.consecutiveFailures = 0;
            return ended;
        } catch (RuntimeException e) {
            return failedToPoll(detachedScan, e);
        }
    }

    private boolean failedToPoll(DetachedScan detachedScan, RuntimeException failure) {
        detachedScan.consecutiveFailures++;
        if (detachedScan.consecutiveFailures < CONSECUTIVE_FAILURES_BEFORE_ENDED) {
            return false;
        }
        eventLog.warn("Scan end check failed " + detachedScan.consecutiveFailures
                + " times in a row, treating the scan as ended: " + failure.getClass().getSimpleName());
        return stopWatching(detachedScan);
    }

    private boolean stopWatching(DetachedScan detachedScan) {
        try {
            detachedScan.scan.stopWatching();
        } catch (RuntimeException e) {
            eventLog.warn("Scan stop watching failed: " + e.getClass().getSimpleName());
        }
        return true;
    }

    private void scheduleNextPoll() {
        if (!detached.isEmpty() && !pollScheduled) {
            pollScheduled = true;
            endPoller.pollLater(this::pollDetached);
        }
    }

    private List<RunningScan> untrackAll() {
        List<RunningScan> untracked = List.copyOf(scans);
        scans.removeAll(untracked);
        return untracked;
    }

    private void tryFail(RunningScan scan, String reason) {
        try {
            scan.failWith(reason);
        } catch (RuntimeException e) {
            eventLog.warn("Scan failure report failed: " + e.getClass().getSimpleName());
        }
    }

    private void tryCancel(RunningScan scan) {
        try {
            scan.cancel();
        } catch (RuntimeException e) {
            eventLog.warn("Scan cancel failed: " + e.getClass().getSimpleName());
        }
    }
}
