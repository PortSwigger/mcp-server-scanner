package com.mcpscanner.checks.catalog.oauthauthorizationconsent;

import burp.api.montoya.scanner.audit.issues.AuditIssueConfidence;
import com.mcpscanner.checks.api.SignedInProbe;
import com.mcpscanner.checks.api.SkipReason;
import com.mcpscanner.checks.shared.oauth.AuthorizationServer;
import com.mcpscanner.checks.shared.oauth.OAuthHttp;

import java.util.List;
import java.util.Optional;
import java.util.Set;

final class ScopeGrantJudge {

    private final AuthorizationServer server;
    private final OAuthHttp http;
    private final ProbeTokens tokens;
    private final ProbeSkips skips;

    ScopeGrantJudge(AuthorizationServer server, OAuthHttp http, ProbeTokens tokens, ProbeSkips skips) {
        this.server = server;
        this.http = http;
        this.tokens = tokens;
        this.skips = skips;
    }

    Optional<AuditIssueConfidence> judge(ProbeClient own, IssuedCode code, List<String> extra, FindingDraft draft) {
        if (server.tokenEndpoint().isEmpty()) {
            draft.fact(SignedInFacts.SCOPE_UNREADABLE + "the authorization server advertises no token endpoint.");
            return Optional.of(AuditIssueConfidence.TENTATIVE);
        }
        Redemption redemption = new CodeRedeemer(http, server.tokenEndpoint().get(), server.resource(), own,
                tokens.ledgerFor(own)).redeem(code);
        redemption.exchange().ifPresent(exchange -> draft.evidence(List.of(exchange)));
        if (redemption.accessToken().isEmpty()) {
            draft.fact(SignedInFacts.SCOPE_UNREADABLE + "the token endpoint issued no access token ("
                    + redemption.status() + "), as for a confidential client.");
            return Optional.of(AuditIssueConfidence.TENTATIVE);
        }
        if (redemption.scope().isEmpty()) {
            draft.fact(SignedInFacts.SCOPE_UNREADABLE + "the token response has no scope.");
            return Optional.of(AuditIssueConfidence.TENTATIVE);
        }
        if (!Set.of(redemption.scope().get().split(" ")).containsAll(extra)) {
            skips.notRun(SignedInProbe.SCOPE_UPGRADE, SkipReason.notApplicable("the server narrowed the scope to \""
                    + redemption.scope().get() + "\""));
            return Optional.empty();
        }
        draft.fact(SignedInFacts.scopeGranted(redemption.scope().get(), own.credentials().secret().isPresent()));
        return Optional.of(AuditIssueConfidence.FIRM);
    }
}
