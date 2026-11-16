package com.mcpscanner.automation;

import com.mcpscanner.access.mining.MiningListener;
import com.mcpscanner.access.mining.MiningReport;
import com.mcpscanner.access.mining.WriteCallApproval;

import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutionException;

public final class HeadlessMining {

    private final MiningStart mining;

    public HeadlessMining(MiningStart mining) {
        this.mining = mining;
    }

    public MiningReport mineEveryUser() {
        CompletableFuture<MiningReport> finished = new CompletableFuture<>();
        mining.start(completing(finished), WriteCallApproval.REFUSE)
                .orElseThrow(() -> new IllegalStateException("Collecting IDs did not start: not connected or already running"));
        return completed(awaited(finished));
    }

    private static MiningReport completed(MiningReport report) {
        if (!report.stop().completed()) {
            throw new IllegalStateException(report.summary() + " " + report.warnings());
        }
        return report;
    }

    private static MiningReport awaited(CompletableFuture<MiningReport> finished) {
        try {
            return finished.get();
        } catch (InterruptedException interrupted) {
            Thread.currentThread().interrupt();
            throw new IllegalStateException("Interrupted while collecting IDs", interrupted);
        } catch (ExecutionException failed) {
            throw new IllegalStateException("Collecting IDs failed", failed.getCause());
        }
    }

    private static MiningListener completing(CompletableFuture<MiningReport> finished) {
        return MiningListener.onFinished(finished::complete);
    }
}
