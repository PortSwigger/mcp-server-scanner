package com.mcpscanner.access.comparison;

import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import com.mcpscanner.checks.api.AccessOutcome;
import com.mcpscanner.checks.api.Principal;
import com.mcpscanner.checks.api.crossidentity.AnonymousReply;
import com.mcpscanner.checks.api.crossidentity.DecisionLog;
import com.mcpscanner.checks.api.crossidentity.OperationReply;
import com.mcpscanner.checks.api.crossidentity.OperationSeed;
import com.mcpscanner.checks.api.crossidentity.SessionAdmission;
import com.mcpscanner.mcp.McpHeaders;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

final class ItemComparison {

    private final OperationSeed seed;
    private final Principal owner;
    private final List<Principal> compared;
    private final ComparisonContext context;
    private final Outcomes outcomes;
    private final DecisionLog log;

    ItemComparison(OperationSeed seed, Principal owner, List<Principal> compared, ComparisonContext context,
                   DecisionLog log) {
        this.seed = seed;
        this.owner = owner;
        this.compared = compared;
        this.context = context;
        this.outcomes = new Outcomes(context.ports().outcomes(), seed.item());
        this.log = log;
    }

    List<Finding> compare(HttpRequestResponse ownerExchange) {
        List<Finding> findings = findings(OperationReply.of(ownerExchange));
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
            return notCompared("baseline_unusable", owner.name() + "'s own call " + UnusableReply.describe(ownerReply),
                    AccessOutcome.NOT_RUN);
        }
        OperationReply anonymous = anonymousReply();
        if (!anonymous.answered()) {
            return notCompared("anonymous_unanswered", "the call without credentials got no response, so there is "
                    + "nothing to compare against", AccessOutcome.ERROR);
        }
        if (ownerReply.sameResult(anonymous)) {
            return notCompared("anonymous_operation_success", "Anonymous already gets " + owner.name()
                    + "'s result, so anyone can reach it", AccessOutcome.SAME_RESULT);
        }
        Map<Principal, Replay> replays = replays();
        if (anonymous.success() && replays.values().stream().map(Replay::reply).noneMatch(anonymous::sameResult)) {
            return notCompared("anonymous_operation_success", "the call also succeeds without credentials, so "
                    + "the users' results cannot be told apart from Anonymous's", AccessOutcome.DIFFERENT_RESULT);
        }
        outcomes.recordAnonymous(Outcomes.compared(anonymous, ownerReply));
        IdentityFindings identities = new IdentityFindings(seed, owner, ownerReply,
                new AnonymousReply(anonymous.exchange().request(), anonymous), context, log, outcomes);
        return replays.entrySet().stream()
                .flatMap(replay -> identities.of(replay.getKey(), replay.getValue()).stream())
                .toList();
    }

    private OperationReply anonymousReply() {
        HttpRequest sessionless = context.requests().anonymous(seed.request()).withRemovedHeader(McpHeaders.SESSION_ID);
        SessionAdmission admission = context.sessions().admit(Principal.ANONYMOUS_ID, sessionless,
                seed.stateful());
        return context.transport().reply(admission.request().orElse(sessionless));
    }

    private Map<Principal, Replay> replays() {
        Map<Principal, Replay> replays = new LinkedHashMap<>();
        compared.forEach(principal -> replays.put(principal, replay(principal)));
        return replays;
    }

    private Replay replay(Principal principal) {
        SessionAdmission admission = context.sessions().admit(principal.id(),
                context.requests().as(principal, seed.request()), seed.stateful());
        return Replay.of(admission, context.transport()::reply);
    }

    private List<Finding> notCompared(String decision, String reason, AccessOutcome anonymous) {
        log.record(decision);
        outcomes.recordAll(compared, AccessOutcome.NOT_RUN);
        outcomes.recordAnonymous(anonymous);
        outcomes.recordNotCompared(reason);
        return List.of();
    }
}
