package com.mcpscanner.access.comparison;

import com.mcpscanner.checks.api.AccessOutcome;
import com.mcpscanner.checks.api.Principal;
import com.mcpscanner.checks.api.crossidentity.AnonymousReply;
import com.mcpscanner.checks.api.crossidentity.DecisionLog;
import com.mcpscanner.checks.api.crossidentity.OperationReply;
import com.mcpscanner.checks.api.crossidentity.OperationSeed;
import com.mcpscanner.checks.api.crossidentity.SessionAdmission;

import java.util.List;
import java.util.Map;
import java.util.concurrent.Executor;

final class ItemComparison {

    private final OperationSeed seed;
    private final Principal owner;
    private final List<Principal> compared;
    private final ComparisonContext context;
    private final Outcomes outcomes;
    private final DecisionLog log;
    private final OperationReply anonymous;
    private final Executor identities;
    private final PrincipalFanOut fanOut;

    ItemComparison(OperationSeed seed, Principal owner, List<Principal> compared, ComparisonContext context,
                   DecisionLog log, SyntheticReplies synthetic, Executor identities) {
        this.identities = identities;
        this.fanOut = new PrincipalFanOut(identities);
        this.seed = seed;
        this.owner = owner;
        this.compared = compared;
        this.context = context;
        this.outcomes = synthetic.outcomes();
        this.anonymous = synthetic.noCredential();
        this.log = log;
    }

    List<Finding> compare(OperationReply ownerReply) {
        List<Finding> findings = findings(ownerReply);
        List<Finding> filed = findings.stream().filter(Finding::filed).toList();
        log.summarize(outcomes.summary() + "; " + filed.size() + " issue(s)" + possible(findings.size() - filed.size()));
        findings.forEach(finding -> outcomes.recordFinding(finding.principal(), finding.accessFinding(owner)));
        return filed;
    }

    private static String possible(int count) {
        return count == 0 ? "" : ", " + count + " possible";
    }

    private List<Finding> findings(OperationReply ownerReply) {
        if (!ownerReply.substantive()) {
            return notCompared("baseline_unusable", owner.name() + "'s own call " + UnusableReply.describe(ownerReply));
        }
        if (!anonymous.answered()) {
            return notCompared("anonymous_unanswered", "the call without credentials got no response, so there is "
                    + "nothing to compare against");
        }
        if (ownerReply.sameResult(anonymous)) {
            return notCompared("anonymous_operation_success", Principal.ANONYMOUS_NAME + " already gets " + owner.name()
                    + "'s result, so anyone can reach it");
        }
        Map<Principal, Replay> replays = replays();
        if (anonymous.success() && replays.values().stream().map(Replay::reply).noneMatch(anonymous::sameResult)) {
            return notCompared("anonymous_operation_success", "the call also succeeds without credentials, so "
                    + "the users' results cannot be told apart from " + Principal.ANONYMOUS_NAME + "'s");
        }
        IdentityFindings perIdentity = new IdentityFindings(seed, owner, ownerReply,
                new AnonymousReply(anonymous.exchange().request(), anonymous), context, log, outcomes, identities);
        return fanOut.each(compared, principal -> perIdentity.of(principal, replays.get(principal))).values().stream()
                .flatMap(List::stream)
                .toList();
    }

    private Map<Principal, Replay> replays() {
        return fanOut.each(compared, this::replay);
    }

    private Replay replay(Principal principal) {
        SessionAdmission admission = context.sessions().admit(principal.id(),
                context.requests().as(principal, seed.request()), seed.stateful());
        return Replay.of(admission, context.transport()::reply);
    }

    private List<Finding> notCompared(String decision, String reason) {
        log.record(decision);
        outcomes.recordAll(compared, AccessOutcome.NOT_RUN);
        outcomes.recordNotCompared(reason);
        return List.of();
    }
}
