package com.mcpscanner.scan;

import burp.api.montoya.scanner.audit.Audit;
import org.junit.jupiter.api.Test;

import java.util.concurrent.atomic.AtomicInteger;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

class BurpAuditRunTest {

    private final Audit audit = mock(Audit.class);
    private final BurpAuditRun run = new BurpAuditRun(audit);
    private final AtomicInteger ends = new AtomicInteger();

    @Test
    void cancellingDeletesTheAuditAndEndsItWithoutReadingItsIssues() {
        run.whenEnded(ends::incrementAndGet);

        run.cancel();

        verify(audit).delete();
        verify(audit, never()).issues();
        assertThat(ends).hasValue(1);
    }

    @Test
    void anAuditBurpReportsFinishedEndsOnceHoweverOftenItIsPolled() {
        run.whenEnded(ends::incrementAndGet);
        when(audit.statusMessage()).thenReturn("Finished");

        run.activity();
        run.activity();
        run.cancel();

        assertThat(ends).hasValue(1);
    }

    @Test
    void aListenerAddedAfterTheEndRunsAtOnce() {
        run.cancel();

        run.whenEnded(ends::incrementAndGet);

        assertThat(ends).hasValue(1);
    }

    @Test
    void aRunningAuditDoesNotEnd() {
        run.whenEnded(ends::incrementAndGet);
        when(audit.statusMessage()).thenReturn("Auditing");

        run.activity();

        assertThat(ends).hasValue(0);
    }

    @Test
    void aFinishedAuditStaysTrackedSoTheScanBarKeepsItsOldBehaviour() {
        when(audit.statusMessage()).thenReturn("Finished");
        run.activity();

        assertThat(run.isFinished()).isFalse();
    }
}
