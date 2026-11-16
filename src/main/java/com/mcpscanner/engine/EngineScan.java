package com.mcpscanner.engine;

import burp.api.montoya.scanner.audit.issues.AuditIssue;

import java.time.Clock;
import java.time.Instant;
import java.util.List;
import java.util.Optional;
import java.util.Queue;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ConcurrentLinkedQueue;
import java.util.function.IntSupplier;

public final class EngineScan {

    private final long id;
    private final ScanLabel label;
    private final Clock clock;
    private final Instant startedAt;
    private final Runnable changed;
    private final IntSupplier watchedPayloads;
    private final ScanLifecycle lifecycle = new ScanLifecycle();
    private final PauseGate pauseGate = new PauseGate();
    private final ScanCounters counters = new ScanCounters();
    private final IssueTally issues = new IssueTally();
    private final Bounded<ScanError> errors = new Bounded<>(ScanErrors.KEPT);
    private final Queue<RunningInvocation> nowRunning = new ConcurrentLinkedQueue<>();
    private final CompletableFuture<ScanProgress> completion = new CompletableFuture<>();
    private volatile SkipCause cancelCause = SkipCause.SCAN_CANCELLED;

    public EngineScan(long id, ScanLabel label, Clock clock, Runnable changed, IntSupplier watchedPayloads) {
        this.id = id;
        this.label = label;
        this.clock = clock;
        this.startedAt = clock.instant();
        this.changed = changed;
        this.watchedPayloads = watchedPayloads;
    }

    public long id() {
        return id;
    }

    public ScanLabel label() {
        return label;
    }

    public ScanSnapshot snapshot() {
        Bounded.Kept<ScanError> keptErrors = errors.kept();
        return new ScanSnapshot(id, label, lifecycle.status(pauseGate.paused()), startedAt, lifecycle.endedAt(),
                progress(), counters.requests(), new ScanErrors(keptErrors.latest(), keptErrors.total()),
                List.copyOf(nowRunning), issues.snapshot());
    }

    public CompletableFuture<ScanProgress> completion() {
        return completion;
    }

    public void pause() {
        if (!lifecycle.ended() && pauseGate.pause()) {
            changed.run();
        }
    }

    public void resume() {
        if (pauseGate.paused()) {
            pauseGate.resume().forEach(ScanTask::schedule);
            changed.run();
        }
    }

    public void cancel() {
        cancel(SkipCause.SCAN_CANCELLED);
    }

    public void abort(String reason) {
        failed(Optional.empty(), "", Optional.empty(), reason);
        cancel();
    }

    void cancel(SkipCause cause) {
        if (lifecycle.cancel()) {
            cancelCause = cause;
            pauseGate.release().forEach(ScanTask::drop);
            changed.run();
        }
    }

    boolean cancelled() {
        return lifecycle.cancelled();
    }

    boolean ended() {
        return lifecycle.ended();
    }

    Optional<Instant> endedAt() {
        return lifecycle.endedAt();
    }

    PauseGate pauseGate() {
        return pauseGate;
    }

    void plan(int invocations) {
        counters.plan(invocations);
        changed.run();
    }

    void completed(List<AuditIssue> found, String testedRequest) {
        issues.add(found, Optional.ofNullable(testedRequest));
        counters.complete();
        changed.run();
    }

    void skip(RegisteredCheck check) {
        counters.skip(check);
        changed.run();
    }

    void requestSent() {
        counters.requestSent();
        changed.run();
    }

    void credit(List<AuditIssue> added, Optional<String> testedRequest) {
        if (!added.isEmpty()) {
            issues.add(added, testedRequest);
            changed.run();
        }
    }

    void failed(Optional<String> check, String requestUrl, Optional<String> field, String reason) {
        errors.add(new ScanError(clock.instant(), check, requestUrl, field, reason));
        changed.run();
    }

    void started(RunningInvocation invocation) {
        nowRunning.add(invocation);
        changed.run();
    }

    void ended(RunningInvocation invocation) {
        nowRunning.remove(invocation);
        changed.run();
    }

    boolean finish() {
        if (!lifecycle.end(clock.instant())) {
            return false;
        }
        counters.reportSkipped(cancelCause);
        completion.complete(progress());
        changed.run();
        return true;
    }

    private ScanProgress progress() {
        return counters.progress(issues.total(), lifecycle.cancelled(), watchedPayloads.getAsInt());
    }
}
