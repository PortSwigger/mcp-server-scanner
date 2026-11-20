package com.mcpscanner.access.comparison;

import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.scanner.audit.issues.AuditIssue;
import com.mcpscanner.access.AccessComparisonRun;
import com.mcpscanner.checks.api.CheckLog;
import com.mcpscanner.checks.api.Principal;
import com.mcpscanner.checks.api.PrincipalRoster;
import com.mcpscanner.checks.api.crossidentity.ComparedPrincipals;
import com.mcpscanner.checks.api.crossidentity.DecisionLog;
import com.mcpscanner.checks.api.crossidentity.OperationReply;
import com.mcpscanner.checks.api.crossidentity.OperationSeed;
import com.mcpscanner.checks.api.crossidentity.OwnerSelection;

import java.util.List;
import java.util.Optional;
import java.util.concurrent.Executor;
import java.util.concurrent.atomic.AtomicReference;

final class CrossIdentityComparisonRun implements AccessComparisonRun {

    private final PrincipalRoster roster;
    private final ComparisonContext context;
    private final CheckLog log;
    private final SameCredentialNotice notice;
    private final AccessIssues issues;
    private final SyntheticCalls synthetic;
    private final AtomicReference<Optional<String>> liveSession = new AtomicReference<>(Optional.empty());

    CrossIdentityComparisonRun(PrincipalRoster roster, ComparisonContext context, CheckLog log,
                               SameCredentialNotice notice, SyntheticCalls synthetic) {
        this.synthetic = synthetic;
        this.roster = roster;
        this.context = context;
        this.log = log;
        this.notice = notice;
        this.issues = new AccessIssues(context.ports().replays());
    }

    @Override
    public List<AuditIssue> compare(HttpRequestResponse ownerExchange, Executor identities) {
        return OperationSeed.of(ownerExchange.request())
                .map(seed -> compare(seed, ownerExchange, identities))
                .orElse(List.of());
    }

    private List<AuditIssue> compare(OperationSeed seed, HttpRequestResponse ownerExchange, Executor identities) {
        seed.sessionId().ifPresent(sessionId -> liveSession.set(Optional.of(sessionId)));
        Principal owner = OwnerSelection.of(seed.request(), roster);
        ComparedPrincipals principals = ComparedPrincipals.of(roster, owner);
        principals.copies().forEach(notice::notice);
        DecisionLog decisions = new DecisionLog(log, seed.label());
        OperationReply ownerReply = OperationReply.of(ownerExchange);
        SyntheticReplies replies = synthetic.call(seed, ownerReply,
                new Outcomes(context.ports().outcomes(), seed.item()), new PrincipalFanOut(identities));
        if (principals.compared().isEmpty()) {
            decisions.record("no_peer_profile");
            return List.of();
        }
        return new ItemComparison(seed, owner, principals.compared(), context, decisions, replies, identities)
                .compare(ownerReply)
                .stream()
                .map(finding -> issues.render(seed, finding))
                .toList();
    }

    @Override
    public void close() {
        context.sessions().deleteAll(liveSession.get());
    }
}
