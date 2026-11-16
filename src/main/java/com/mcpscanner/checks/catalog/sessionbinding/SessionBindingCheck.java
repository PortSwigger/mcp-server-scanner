package com.mcpscanner.checks.catalog.sessionbinding;

import burp.api.montoya.http.Http;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.scanner.ConsolidationAction;
import burp.api.montoya.scanner.audit.issues.AuditIssue;
import com.mcpscanner.auth.AuthStrategy;
import com.mcpscanner.checks.api.CheckDescriptor;
import com.mcpscanner.checks.api.CheckLog;
import com.mcpscanner.checks.api.ConnectionScoped;
import com.mcpscanner.checks.api.Principal;
import com.mcpscanner.checks.api.PrincipalRoster;
import com.mcpscanner.checks.api.ReplayPermission;
import com.mcpscanner.checks.api.RequestCheck;
import com.mcpscanner.checks.api.SkipReason;
import com.mcpscanner.checks.api.SkipSubject;
import com.mcpscanner.checks.api.crossidentity.AbsentValues;
import com.mcpscanner.checks.api.crossidentity.ComparedPrincipals;
import com.mcpscanner.checks.api.crossidentity.DecisionLog;
import com.mcpscanner.checks.api.crossidentity.OpenedSessions;
import com.mcpscanner.checks.api.crossidentity.IssuedSession;
import com.mcpscanner.checks.api.crossidentity.OperationSeed;
import com.mcpscanner.checks.api.crossidentity.ReplayedOperation;
import com.mcpscanner.checks.api.crossidentity.OwnerSelection;
import com.mcpscanner.checks.api.crossidentity.PrincipalRequests;
import com.mcpscanner.checks.api.crossidentity.ProbeKit;
import com.mcpscanner.checks.api.crossidentity.ProbeTransport;
import com.mcpscanner.checks.api.crossidentity.ReplaySkips;
import com.mcpscanner.checks.issue.IssueIdentity;
import com.mcpscanner.logging.McpEventLog;

import java.util.List;
import java.util.Optional;
import java.util.function.Supplier;

public final class SessionBindingCheck implements RequestCheck, ConnectionScoped {

    private static final SkipReason STATELESS = SkipReason.notApplicable("the server issues no Mcp-Session-Id");
    private static final SkipReason OWNER_INITIALIZE_FAILED =
            SkipReason.transportFailure("the owner's initialize was refused or got no reply, so no probe session could be opened");
    private static final SkipReason EVERY_IDENTITY_PROBED = SkipReason.alreadyAudited("every compared identity was already probed on this host");

    private final CheckLog log;
    private final Supplier<AuthStrategy> primaryAuth;
    private final Supplier<PrincipalRoster> principals;
    private final ReplayPermission replayPermission;
    private final IdentityClaims claims = new IdentityClaims();

    public SessionBindingCheck(McpEventLog eventLog, Supplier<AuthStrategy> primaryAuth,
                               Supplier<PrincipalRoster> principals, ReplayPermission replayPermission) {
        this.log = new CheckLog(eventLog, SessionBindingDescriptor.ID);
        this.primaryAuth = primaryAuth;
        this.principals = principals;
        this.replayPermission = replayPermission;
    }

    @Override
    public CheckDescriptor descriptor() {
        return SessionBindingDescriptor.DESCRIPTOR;
    }

    @Override
    public boolean requiresReply() {
        return true;
    }

    @Override
    public ConsolidationAction consolidate(AuditIssue existingIssue, AuditIssue newIssue) {
        return IssueIdentity.keepStrongerOfSameSubject(existingIssue, newIssue);
    }

    @Override
    public void clearConnectionState() {
        claims.clear();
    }

    @Override
    public List<AuditIssue> audit(HttpRequestResponse baseRequestResponse, Http http) {
        Optional<OperationSeed> seed = OperationSeed.of(baseRequestResponse.request());
        if (seed.isEmpty()) {
            log.notRun(SkipSubject.of(baseRequestResponse), ReplaySkips.NOT_AN_OPERATION);
            return List.of();
        }
        return audit(seed.get(), DecisionLog.of(log, seed.get()), http);
    }

    private List<AuditIssue> audit(OperationSeed seed, DecisionLog decisions, Http http) {
        return applicable(seed, decisions) ? probe(seed, decisions, http) : List.of();
    }

    private boolean applicable(OperationSeed seed, DecisionLog decisions) {
        if (!replayPermission.permitsReplay(seed.item())) {
            decisions.record("write_replay_not_confirmed");
            decisions.notRun(ReplaySkips.WRITE_REPLAY_NOT_CONFIRMED);
            return false;
        }
        return true;
    }

    private List<AuditIssue> probe(OperationSeed seed, DecisionLog decisions, Http http) {
        PrincipalRoster roster = principals.get();
        Principal owner = OwnerSelection.of(seed.request(), roster);
        List<Principal> compared = ComparedPrincipals.of(roster, owner).compared();
        if (compared.isEmpty()) {
            decisions.notRun(ReplaySkips.NO_COMPARED_IDENTITY);
            return List.of();
        }
        List<Principal> claimed = claims.claim(seed.request(), compared);
        if (claimed.isEmpty()) {
            decisions.record("session_binding:no_unprobed_identity");
            decisions.notRun(EVERY_IDENTITY_PROBED);
            return List.of();
        }
        OpenedSessions opened = new OpenedSessions();
        PrincipalRequests requests = new PrincipalRequests(primaryAuth, roster);
        ProbeTransport transport = new ProbeTransport(http, decisions);
        try {
            IssuedSession<OperationSeed> sessioned = OwnerSession.of(seed, owner, requests, transport, opened);
            if (sessioned.value().isEmpty()) {
                return withoutOwnerSession(seed, claimed, decisions, sessioned.outcome());
            }
            ProbeKit kit = ProbeKit.of(sessioned.value().get(), owner, requests, transport, new AbsentValues(), decisions,
                    opened);
            return settled(seed, new SessionBindingRun(kit, claimed).run());
        } catch (RuntimeException failure) {
            claims.releaseUnprobed(seed.request(), claimed);
            throw failure;
        } finally {
            opened.deleteAll(http, seed.sessionId());
        }
    }

    private List<AuditIssue> withoutOwnerSession(OperationSeed seed, List<Principal> claimed,
                                                 DecisionLog decisions, IssuedSession.Outcome outcome) {
        claims.releaseUnprobed(seed.request(), claimed);
        if (outcome == IssuedSession.Outcome.INITIALIZE_FAILED) {
            decisions.record("session_binding:owner_initialize_failed");
            decisions.notRun(OWNER_INITIALIZE_FAILED);
        } else {
            decisions.record("session_binding:skipped_stateless_transport");
            decisions.notRun(STATELESS);
        }
        return List.of();
    }

    private List<AuditIssue> settled(OperationSeed seed, List<IdentityOutcome> outcomes) {
        outcomes.forEach(outcome -> claims.settle(seed.request(), outcome));
        ReplayedOperation replayed = ReplayedOperation.of(seed, replayPermission);
        return outcomes.stream()
                .flatMap(outcome -> outcome.issues().stream())
                .map(issue -> SessionBindingIssues.render(seed, replayed, issue))
                .toList();
    }
}
