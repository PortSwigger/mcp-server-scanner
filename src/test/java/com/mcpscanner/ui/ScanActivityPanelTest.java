package com.mcpscanner.ui;

import com.mcpscanner.scan.ScanActivity;
import com.mcpscanner.scan.ScanMode;
import com.mcpscanner.testutil.ManualReadScheduler;
import com.mcpscanner.ui.widgets.DaemonReadScheduler;
import com.mcpscanner.ui.widgets.UiReads;
import org.junit.jupiter.api.Test;

import javax.swing.SwingUtilities;
import java.time.Duration;

import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;

import static com.mcpscanner.testutil.ManualReadScheduler.immediateReads;
import static com.mcpscanner.testutil.Polling.within;
import static org.assertj.core.api.Assertions.assertThat;

class ScanActivityPanelTest {

    private static final String MCP_ONLY_RESULTS = ScanModeText.of(ScanMode.MCP_ONLY).resultsLocation();
    private static final String BURP_RESULTS = ScanModeText.of(ScanMode.MCP_AND_BURP).resultsLocation();

    private final AtomicReference<ScanActivity> activity = new AtomicReference<>(ScanActivity.burpAudit(2, 1));
    private final ScanActivityPanel panel = new ScanActivityPanel(activity::get, () -> {}, immediateReads());

    @Test
    void aBurpAuditCountsItsRequestsWithSingularAndPluralNouns() {
        panel.refresh();

        assertThat(panel.summaryText()).isEqualTo("1 Burp audit · 2 requests · 1 issue");
    }

    @Test
    void aBurpAuditPointsAtTheDashboardAndStopDeletesItsTasks() {
        panel.refresh();

        assertThat(panel.summaryTooltip()).isEqualTo("Burp audits: results in " + BURP_RESULTS);
        assertThat(panel.stopButton().getToolTipText())
                .isEqualTo("Stop and delete the Burp audit tasks this extension started");
    }

    @Test
    void anMcpOnlyScanCountsTheProbesItHasRun() {
        activity.set(ScanActivity.mcpOnlyScan(4, 2));

        panel.refresh();

        assertThat(panel.summaryText()).isEqualTo("1 extension scan · 4 probes run · 2 issues");
    }

    @Test
    void anMcpOnlyScanPointsAtTargetIssuesAndStopOnlyStopsIt() {
        activity.set(ScanActivity.mcpOnlyScan(4, 2));

        panel.refresh();

        assertThat(panel.summaryTooltip()).isEqualTo("Extension scans: results in " + MCP_ONLY_RESULTS);
        assertThat(panel.stopButton().getToolTipText()).isEqualTo("Stop the running extension scans");
    }

    @Test
    void runningBothKindsDescribesEachAndSumsTheIssues() {
        activity.set(ScanActivity.mcpOnlyScan(4, 2).plus(ScanActivity.burpAudit(120, 1)));

        panel.refresh();

        assertThat(panel.summaryText()).isEqualTo("1 extension scan · 4 probes run · 1 Burp audit · 120 requests · 3 issues");
        assertThat(panel.summaryTooltip()).isEqualTo(
                "Extension scans: results in " + MCP_ONLY_RESULTS + ". Burp audits: results in " + BURP_RESULTS);
        assertThat(panel.stopButton().getToolTipText()).isEqualTo(
                "Stop the running extension scans. Stop and delete the Burp audit tasks this extension started");
    }

    @Test
    void activeScanKeepsPolling() {
        panel.refresh();

        assertThat(panel.isPolling()).isTrue();
    }

    @Test
    void idleActivityHidesThePanelAndStopsPolling() {
        panel.refresh();
        activity.set(ScanActivity.idle());

        panel.refresh();

        assertThat(panel.isVisible()).isFalse();
        assertThat(panel.isPolling()).isFalse();
    }

    @Test
    void disposeStopsPolling() {
        panel.refresh();

        panel.dispose();

        assertThat(panel.isPolling()).isFalse();
    }

    @Test
    void refreshingOnTheEdtReadsActivityOffTheEdt() throws Exception {
        DaemonReadScheduler scheduler = new DaemonReadScheduler();
        AtomicReference<Boolean> readOnEdt = new AtomicReference<>();
        ScanActivityPanel background = new ScanActivityPanel(() -> {
            readOnEdt.compareAndSet(null, SwingUtilities.isEventDispatchThread());
            return ScanActivity.burpAudit(3, 1);
        }, () -> {}, UiReads.background(scheduler, (message, failure) -> { }));
        try {
            SwingUtilities.invokeAndWait(background::refresh);

            within(Duration.ofSeconds(5)).until(() -> readOnEdt.get() != null);
            assertThat(readOnEdt.get()).isFalse();
            within(Duration.ofSeconds(5)).until(() -> "1 Burp audit · 3 requests · 1 issue".equals(background.summaryText()));
        } finally {
            scheduler.shutdown();
            background.dispose();
        }
    }

    @Test
    void aReadArrivingAfterDisposeDoesNotRestartPolling() {
        ManualReadScheduler scheduler = new ManualReadScheduler();
        ScanActivityPanel late = new ScanActivityPanel(activity::get, () -> {}, scheduler.reads());
        late.refresh();

        late.dispose();
        scheduler.runNext();

        assertThat(late.isPolling()).isFalse();
    }

    @Test
    void stopRunsOffTheCallersThread() {
        ManualReadScheduler scheduler = new ManualReadScheduler();
        AtomicInteger stops = new AtomicInteger();
        ScanActivityPanel deferred = new ScanActivityPanel(activity::get, stops::incrementAndGet, scheduler.reads());

        deferred.stopButton().doClick();

        assertThat(stops).hasValue(0);
        scheduler.runNext();
        assertThat(stops).hasValue(1);
    }
}
