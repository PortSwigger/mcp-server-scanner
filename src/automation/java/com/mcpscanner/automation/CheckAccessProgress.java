package com.mcpscanner.automation;

import burp.api.montoya.http.Http;
import burp.api.montoya.scanner.audit.issues.AuditIssue;
import com.mcpscanner.access.AccessRunListener;
import com.mcpscanner.access.AccessRunSummary;

import java.util.List;
import java.util.Optional;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.Consumer;

public final class CheckAccessProgress implements AccessRunListener, Consumer<AuditIssue> {

    private final ProbeCounter requests = ProbeCounter.throughTheExtensionProxy();
    private final List<ReportedIssue> filed = new CopyOnWriteArrayList<>();
    private final AtomicReference<Stage> stage = new AtomicReference<>();

    public Http counted(Http http) {
        return requests.wrap(http);
    }

    public Optional<CheckAccessStatus> status() {
        return Optional.ofNullable(stage.get()).map(current -> new CheckAccessStatus(current.phase(),
                current.checked(), current.total(), requests.sent(), requests.reached(), filed, current.reason()));
    }

    boolean active() {
        Stage current = stage.get();
        return current != null && !current.phase().ended();
    }

    void begin() {
        requests.reset();
        filed.clear();
        stage.set(new Stage(CheckAccessPhase.DISCOVERING, 0, 0, null));
    }

    void mining() {
        stage.set(new Stage(CheckAccessPhase.MINING, 0, 0, null));
    }

    void running(int total) {
        stage.set(new Stage(CheckAccessPhase.RUNNING, 0, total, null));
    }

    void failed(String reason) {
        stage.updateAndGet(current -> new Stage(CheckAccessPhase.FAILED, current.checked(), current.total(), reason));
    }

    @Override
    public void progress(int done, int total) {
        stage.set(new Stage(CheckAccessPhase.RUNNING, done, total, null));
    }

    @Override
    public void finished(AccessRunSummary summary) {
        stage.set(new Stage(endOf(summary), summary.checked(), summary.total(), summary.stopReason().orElse(null)));
    }

    @Override
    public void accept(AuditIssue issue) {
        filed.add(ReportedIssue.filedByTheExtension(issue));
    }

    private static CheckAccessPhase endOf(AccessRunSummary summary) {
        if (summary.cancelled()) {
            return CheckAccessPhase.CANCELLED;
        }
        return summary.stopReason().isPresent() ? CheckAccessPhase.STOPPED : CheckAccessPhase.FINISHED;
    }

    private record Stage(CheckAccessPhase phase, int checked, int total, String reason) {
    }
}
