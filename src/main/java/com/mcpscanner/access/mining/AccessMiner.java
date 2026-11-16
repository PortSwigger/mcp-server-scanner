package com.mcpscanner.access.mining;

import com.mcpscanner.checks.api.Principal;
import com.mcpscanner.scan.ScanInventory;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionException;
import java.util.concurrent.Executor;
import java.util.stream.Stream;

public final class AccessMiner {

    private static final Executor IN_ORDER = Runnable::run;

    private final MiningSender sender;
    private final MiningSettings settings;
    private final Executor sendWorkers;

    public AccessMiner(MiningSender sender, MiningSettings settings) {
        this(sender, settings, IN_ORDER);
    }

    public AccessMiner(MiningSender sender, MiningSettings settings, Executor sendWorkers) {
        this.sender = sender;
        this.settings = settings;
        this.sendWorkers = sendWorkers;
    }

    public MiningResult mine(ScanInventory inventory, List<Principal> identities, MiningControl control) {
        MiningKit kit = kit(MiningCatalog.of(inventory), control);
        List<IdentityMiner> miners = withAnonymous(identities).stream()
                .map(identity -> new IdentityMiner(identity, settings, kit)).toList();
        for (int pass = 1; pass <= settings.passes(); pass++) {
            List<IdentityMiner> active = miners.stream().filter(IdentityMiner::active).toList();
            if (active.isEmpty()) {
                break;
            }
            runPass(pass, active);
        }
        return classified(miners.stream().map(IdentityMiner::run).toList());
    }

    private MiningKit kit(MiningCatalog catalog, MiningControl control) {
        return new MiningKit(sender, new CallPlanner(catalog, new ToolGate(settings.allowedTools())),
                new ReplySightings(catalog), control, new MiningHalt(control.cancelled()));
    }

    private void runPass(int pass, List<IdentityMiner> active) {
        Map<IdentityMiner, List<CompletableFuture<CallOutcome>>> sent = new LinkedHashMap<>();
        active.forEach(miner -> sent.put(miner, miner.nextPass(pass).stream()
                .map(send -> CompletableFuture.supplyAsync(send, sendWorkers)).toList()));
        try {
            sent.forEach((miner, outcomes) -> miner.absorb(outcomes.stream().map(CompletableFuture::join).toList()));
        } catch (CompletionException failure) {
            sent.values().forEach(outcomes -> outcomes.forEach(outcome -> outcome.cancel(false)));
            throw failure.getCause() instanceof RuntimeException cause ? cause : failure;
        }
    }

    private static MiningResult classified(List<IdentityRun> runs) {
        MiningStop stop = runs.stream().map(IdentityRun::stop).filter(identityStop -> !identityStop.completed()).findFirst()
                .orElse(MiningStop.COMPLETED);
        VisibilityClassifier classifier = new VisibilityClassifier(runs);
        return new MiningResult(classifier.identities(), classifier.warnings(), stop);
    }

    private static List<Principal> withAnonymous(List<Principal> identities) {
        boolean included = identities.stream().anyMatch(identity -> Principal.isAnonymous(identity.id()));
        return included ? identities : Stream.concat(identities.stream(), Stream.of(Principal.anonymous())).toList();
    }
}
