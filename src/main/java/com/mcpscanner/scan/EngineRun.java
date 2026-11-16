package com.mcpscanner.scan;

import com.mcpscanner.engine.EngineScan;
import com.mcpscanner.engine.ScanProgress;

import java.util.function.Consumer;

record EngineRun(EngineScan scan) implements OutcomeReportingScan {

    @Override
    public ScanActivity activity() {
        ScanProgress progress = scan.snapshot().progress();
        return ScanActivity.mcpOnlyScan(progress.completed(), progress.issuesReported());
    }

    @Override
    public boolean isFinished() {
        return scan.completion().isDone();
    }

    @Override
    public boolean outlivesConnection() {
        return false;
    }

    @Override
    public void cancel() {
        scan.cancel();
    }

    @Override
    public void failWith(String reason) {
        scan.abort(reason);
    }

    @Override
    public void whenCompleted(Consumer<ScanOutcome> listener) {
        scan.completion().thenAccept(progress ->
                listener.accept(new ScanOutcome(progress.issuesReported(), progress.cancelled(),
                        progress.watchedPayloads())));
    }

    @Override
    public void whenEnded(Runnable action) {
        whenCompleted(outcome -> action.run());
    }
}
