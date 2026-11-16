package com.mcpscanner.automation;

import com.mcpscanner.access.AccessRow;

import java.util.List;
import java.util.Objects;
import java.util.Optional;
import java.util.concurrent.Executor;

public final class HeadlessCheckAccess {

    private final HeadlessConnection connection;
    private final CheckAccessSteps steps;
    private final CheckAccessProgress progress;
    private final Executor worker;

    public HeadlessCheckAccess(HeadlessConnection connection, CheckAccessSteps steps, CheckAccessProgress progress,
                               Executor worker) {
        this.connection = connection;
        this.steps = steps;
        this.progress = progress;
        this.worker = worker;
    }

    public CheckAccessStatus launch(CheckAccessCommand command) {
        return connection.exclusively(() -> launchConnected(command));
    }

    private CheckAccessStatus launchConnected(CheckAccessCommand command) {
        if (progress.active()) {
            throw new IllegalStateException("Check access is already running");
        }
        connection.connect(command);
        progress.begin();
        worker.execute(this::prepareAndCheck);
        return progress.status().orElseThrow();
    }

    public Optional<CheckAccessStatus> status() {
        return progress.status();
    }

    private void prepareAndCheck() {
        try {
            steps.awaitListings().run();
            progress.mining();
            steps.mineEveryUser().run();
            check(steps.rows().get());
        } catch (RuntimeException failure) {
            progress.failed(Objects.requireNonNullElse(failure.getMessage(), failure.getClass().getSimpleName()));
        }
    }

    private void check(List<AccessRow> rows) {
        progress.running(rows.size());
        steps.checkAccess().start(rows, progress)
                .orElseThrow(() -> new IllegalStateException("Check access did not start"));
    }
}
