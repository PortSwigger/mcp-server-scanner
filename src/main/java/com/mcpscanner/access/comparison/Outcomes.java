package com.mcpscanner.access.comparison;

import com.mcpscanner.checks.api.crossidentity.OperationReply;
import com.mcpscanner.checks.api.AccessFinding;
import com.mcpscanner.checks.api.AccessItemKey;
import com.mcpscanner.checks.api.AccessOutcomeSink;
import com.mcpscanner.checks.api.AccessOutcome;
import com.mcpscanner.checks.api.Principal;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.stream.Collectors;

final class Outcomes {

    private static final String ANONYMOUS = "anonymous";

    private final AccessOutcomeSink ledger;
    private final AccessItemKey item;
    private final Map<String, AccessOutcome> recorded = new LinkedHashMap<>();
    private Optional<String> notCompared = Optional.empty();

    Outcomes(AccessOutcomeSink ledger, AccessItemKey item) {
        this.ledger = ledger;
        this.item = item;
    }

    static AccessOutcome compared(OperationReply reply, OperationReply owner) {
        if (!reply.answered()) {
            return AccessOutcome.ERROR;
        }
        if (owner.sameResult(reply)) {
            return AccessOutcome.SAME_RESULT;
        }
        return reply.success() ? AccessOutcome.DIFFERENT_RESULT : AccessOutcome.REFUSED;
    }

    void record(Principal principal, AccessOutcome outcome) {
        ledger.record(item, principal.id(), outcome);
        recorded.put(principal.name(), outcome);
    }

    void recordAll(List<Principal> principals, AccessOutcome outcome) {
        principals.forEach(principal -> record(principal, outcome));
    }

    void recordAnonymous(AccessOutcome outcome) {
        ledger.recordAnonymous(item, outcome);
        recorded.put(ANONYMOUS, outcome);
    }

    void recordNotCompared(String reason) {
        ledger.recordNotCompared(item, reason);
        notCompared = Optional.of(reason);
    }

    void recordFinding(Principal principal, AccessFinding finding) {
        ledger.recordFinding(item, principal.id(), finding);
    }

    String summary() {
        String outcomes = recorded.entrySet().stream().map(entry -> entry.getKey() + "=" + entry.getValue())
                .collect(Collectors.joining(", ", "outcomes ", ""));
        return notCompared.map(reason -> "not compared: " + reason + "; " + outcomes).orElse(outcomes);
    }
}
