package com.mcpscanner.access.mining;

import com.mcpscanner.identity.OwnedValueStore;
import com.mcpscanner.logging.McpEventLog;
import com.mcpscanner.mcp.McpToolDefinition;
import com.mcpscanner.scan.ScanInventory;

import java.util.List;
import java.util.Optional;
import java.util.concurrent.Executor;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.atomic.AtomicLong;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.Supplier;

public final class AccessMining {

    private final MiningInputs inputs;
    private final MiningSender sender;
    private final MiningPreferences preferences;
    private final MinedValueWriter writer;
    private final ExecutorService worker;
    private final Supplier<Executor> sendWorkers;
    private final McpEventLog log;
    private final MinedIdentitySet mined = new MinedIdentitySet();
    private final AtomicLong connection = new AtomicLong();
    private final AtomicReference<MiningRun> current = new AtomicReference<>();

    public AccessMining(MiningInputs inputs, MiningSender sender, MiningPreferences preferences,
                        OwnedValueStore store, ExecutorService worker, Supplier<Executor> sendWorkers,
                        McpEventLog log) {
        this.inputs = inputs;
        this.sender = sender;
        this.preferences = preferences;
        this.writer = new MinedValueWriter(store, log);
        this.worker = worker;
        this.sendWorkers = sendWorkers;
        this.log = log;
    }

    public Optional<MiningBlocker> blocker() {
        if (running()) {
            return Optional.of(MiningBlocker.RUNNING);
        }
        return inputs.inventory().get().isPresent() ? Optional.empty() : Optional.of(MiningBlocker.NOT_CONNECTED);
    }

    public boolean running() {
        return current.get() != null;
    }

    public boolean minedForCurrentIdentities() {
        return inputs.inventory().get().map(inventory -> mined.matches(plan(inventory).identityIds())).orElse(false);
    }

    public long connection() {
        return connection.get();
    }

    public List<McpToolDefinition> tools() {
        return inputs.inventory().get().map(ScanInventory::tools).orElse(List.of());
    }

    public List<McpToolDefinition> writeTools() {
        return MiningPreferences.writeToolsIn(tools());
    }

    public MiningPreferences preferences() {
        return preferences;
    }

    public Optional<MiningRun> start(MiningListener listener, WriteCallApproval approval) {
        Optional<ScanInventory> inventory = inputs.inventory().get();
        if (inventory.isEmpty()) {
            return Optional.empty();
        }
        MiningRun run = new MiningRun();
        if (!current.compareAndSet(null, run)) {
            return Optional.empty();
        }
        MiningPlan plan = plan(inventory.get());
        WriteCallApproval runApproval = new RunWriteApproval(approval);
        worker.execute(() -> finish(run, plan, listener, mine(run, plan, listener, runApproval)));
        return Optional.of(run);
    }

    public void cancel() {
        Optional.ofNullable(current.get()).ifPresent(MiningRun::cancel);
    }

    public void reset() {
        cancel();
        mined.forget();
        connection.incrementAndGet();
    }

    private MiningPlan plan(ScanInventory inventory) {
        return MiningPlan.of(inventory, inputs.roster().get(), inputs.primaryUserId().get());
    }

    private MiningReport mine(MiningRun run, MiningPlan plan, MiningListener listener, WriteCallApproval approval) {
        try {
            log.info("Collecting IDs started for " + plan.principals().size() + " users and Anonymous");
            MiningResult result = new AccessMiner(sender, preferences.settings(plan.inventory().tools()),
                    sendWorkers.get())
                    .mine(plan.inventory(), plan.principals(),
                            new MiningControl(step -> listener.progressed(plan.nameOf(step.identityId()), step),
                                    run::cancelled, approval));
            MiningStop stop = run.cancelled() ? MiningStop.CANCELLED : result.stop();
            if (stop.completed()) {
                writer.write(result, plan.identityIdsByPrincipal());
                mined.record(plan.identityIds());
            }
            return MiningReportLines.of(new MiningResult(result.identities(), result.warnings(), stop), plan);
        } catch (RuntimeException failure) {
            log.error("Collecting IDs failed: " + failure.getMessage());
            return MiningReport.failed(String.valueOf(failure.getMessage()));
        }
    }

    private void finish(MiningRun run, MiningPlan plan, MiningListener listener, MiningReport report) {
        current.compareAndSet(run, null);
        log.info(report.summary());
        report.warnings().forEach(line -> log.warn("Collecting IDs: " + line));
        listener.finished(report);
    }
}
