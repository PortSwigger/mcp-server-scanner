package com.mcpscanner.access.mining;

import com.mcpscanner.checks.api.Principal;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.function.Supplier;

final class IdentityMiner {

    private final Principal identity;
    private final MiningSettings settings;
    private final MiningKit kit;
    private final RequestAllowance allowance;
    private final StableExchange exchange;
    private final IdentitySightings sightings;
    private final Set<String> sentCalls = ConcurrentHashMap.newKeySet();
    private MiningStop stop = MiningStop.COMPLETED;
    private boolean finished;

    IdentityMiner(Principal identity, MiningSettings settings, MiningKit kit) {
        this.identity = identity;
        this.settings = settings;
        this.kit = kit;
        this.allowance = RequestAllowance.of(settings, kit.planner().mostRequests(settings));
        this.exchange = new StableExchange(kit.sender(), identity, allowance);
        this.sightings = new IdentitySightings(settings.valuesPerArgument());
    }

    boolean active() {
        return !finished;
    }

    List<Supplier<CallOutcome>> nextPass(int pass) {
        List<Supplier<CallOutcome>> sends = new ArrayList<>();
        for (MiningCall call : approved(pass == 1 ? kit.planner().firstPass() : kit.planner().fedPass(sightings))) {
            if (!allowance.reserve(StableExchange.SENDS_PER_CALL)) {
                break;
            }
            sentCalls.add(key(call));
            sends.add(() -> send(pass, call));
        }
        return sends;
    }

    void absorb(List<CallOutcome> outcomes) {
        int found = 0;
        for (CallOutcome outcome : outcomes) {
            found += sightings.add(outcome.sightings());
            stop = stop.completed() ? outcome.stop() : stop;
        }
        finished = !stop.completed() || found == 0 || allowance.exhausted();
    }

    IdentityRun run() {
        return new IdentityRun(identity.id(), sightings, allowance.sent(), allowance.warning(identity.id()), stop);
    }

    private CallOutcome send(int pass, MiningCall first) {
        List<Sighting> found = new ArrayList<>();
        Optional<MiningCall> next = Optional.of(first);
        while (next.isPresent()) {
            MiningCall call = next.get();
            Optional<MiningStop> halted = kit.halt().stop();
            if (halted.isPresent()) {
                return new CallOutcome(found, halted.get());
            }
            Optional<StableExchange.Replies> replies = exchange.send(call);
            if (replies.isEmpty()) {
                kit.halt().rateLimited();
                return new CallOutcome(found, MiningStop.RATE_LIMITED);
            }
            found.addAll(kit.replySightings().stable(call, replies.get().first(), replies.get().second(),
                    OwnerEvidence.of(identity)));
            kit.control().progress().progressed(new MiningStep(identity.id(), pass, allowance.sent()));
            next = nextPage(call, replies.get().first());
        }
        return new CallOutcome(found, MiningStop.COMPLETED);
    }

    private Optional<MiningCall> nextPage(MiningCall call, MiningReply reply) {
        return call instanceof MiningCall.ResourceListing listing && reply.usable()
                ? listing.next(reply.result(), settings.listPages()).map(MiningCall.class::cast)
                        .filter(page -> sentCalls.add(key(page)))
                        .filter(page -> allowance.reserve(StableExchange.SENDS_PER_CALL))
                : Optional.empty();
    }

    private List<MiningCall> approved(List<MiningCall> planned) {
        List<MiningCall> unsent = planned.stream().filter(call -> !sentCalls.contains(key(call)))
                .filter(new DistinctCalls()::firstSeen).toList();
        return new WriteCallScreen(kit.control().writes()).approved(identity.name(), unsent);
    }

    private static String key(MiningCall call) {
        return call.method() + call.params();
    }

    private static final class DistinctCalls {
        private final Set<String> seen = new HashSet<>();

        boolean firstSeen(MiningCall call) {
            return seen.add(key(call));
        }
    }
}
