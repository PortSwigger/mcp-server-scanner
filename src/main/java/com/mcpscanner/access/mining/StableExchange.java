package com.mcpscanner.access.mining;

import com.mcpscanner.checks.api.Principal;

import java.util.Optional;

final class StableExchange {

    static final int SENDS_PER_CALL = 2;
    static final int MOST_SENDS_PER_CALL = SENDS_PER_CALL + 1;

    private final MiningSender sender;
    private final Principal identity;
    private final RequestAllowance allowance;

    StableExchange(MiningSender sender, Principal identity, RequestAllowance allowance) {
        this.sender = sender;
        this.identity = identity;
        this.allowance = allowance;
    }

    Optional<Replies> send(MiningCall call) {
        Optional<MiningReply> first = sent(call);
        Optional<MiningReply> second = first.flatMap(reply -> sent(call));
        if (second.isEmpty()) {
            return Optional.empty();
        }
        return first.get().usable() == second.get().usable() ? Optional.of(new Replies(first.get(), second.get()))
                : retried(call, first.get().usable() ? first.get() : second.get());
    }

    private Optional<Replies> retried(MiningCall call, MiningReply succeeded) {
        if (!allowance.reserve(1)) {
            return Optional.of(new Replies(succeeded, MiningReply.unanswered()));
        }
        return sent(call).map(retry -> new Replies(succeeded, retry));
    }

    private Optional<MiningReply> sent(MiningCall call) {
        MiningReply reply = sender.send(identity, call);
        allowance.recordSend();
        return reply.rateLimited() ? Optional.empty() : Optional.of(reply);
    }

    record Replies(MiningReply first, MiningReply second) {
    }
}
