package com.mcpscanner.scan;

import burp.api.montoya.scanner.audit.Audit;

import java.util.ArrayList;
import java.util.List;
import java.util.Objects;

public final class BurpAuditRun implements RunningScan {

    private static final String FINISHED_STATUS = "finished";

    private final Audit audit;
    private final List<Runnable> endActions = new ArrayList<>();
    private boolean ended;

    public BurpAuditRun(Audit audit) {
        this.audit = Objects.requireNonNull(audit);
    }

    public Audit audit() {
        return audit;
    }

    @Override
    public ScanActivity activity() {
        endIfBurpFinished();
        return ScanActivity.burpAudit(audit.requestCount(), audit.issues().size());
    }

    @Override
    public boolean isFinished() {
        return false;
    }

    @Override
    public boolean outlivesConnection() {
        return true;
    }

    @Override
    public void cancel() {
        audit.delete();
        end();
    }

    @Override
    public boolean pollEnded() {
        endIfBurpFinished();
        return hasEnded();
    }

    @Override
    public void stopWatching() {
        end();
    }

    private synchronized boolean hasEnded() {
        return ended;
    }

    @Override
    public synchronized void whenEnded(Runnable action) {
        if (ended) {
            action.run();
        } else {
            endActions.add(action);
        }
    }

    private void endIfBurpFinished() {
        if (FINISHED_STATUS.equalsIgnoreCase(audit.statusMessage())) {
            end();
        }
    }

    private synchronized void end() {
        if (!ended) {
            ended = true;
            endActions.forEach(Runnable::run);
            endActions.clear();
        }
    }

    @Override
    public boolean equals(Object other) {
        return other instanceof BurpAuditRun run && audit.equals(run.audit);
    }

    @Override
    public int hashCode() {
        return audit.hashCode();
    }

    @Override
    public String toString() {
        return "BurpAuditRun[audit=" + audit + "]";
    }
}
