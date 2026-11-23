package com.mcpscanner.checks.catalog.oauthauthorizationconsent;

import burp.api.montoya.scanner.audit.issues.AuditIssueConfidence;
import com.mcpscanner.checks.api.SignedInProbe;
import com.mcpscanner.checks.shared.oauth.AuthorizationServer;
import com.mcpscanner.checks.shared.oauth.OAuthHttp;

import java.net.URI;
import java.util.List;
import java.util.Optional;

final class ShortcutProbe {

    private final AuthorizationServer server;
    private final OAuthHttp http;
    private final UnattendedAuthorizer authorizer;
    private final TokenAccess access;
    private final ProbeTokens tokens;
    private final String sessionSource;
    private final Optional<String> scope;

    ShortcutProbe(AuthorizationServer server, OAuthHttp http, UnattendedAuthorizer authorizer, TokenAccess access,
                  ProbeTokens tokens, String sessionSource, Optional<String> scope) {
        this.server = server;
        this.http = http;
        this.authorizer = authorizer;
        this.access = access;
        this.tokens = tokens;
        this.sessionSource = sessionSource;
        this.scope = scope;
    }

    ShortcutOutcome probe(SignedInProbe probe, RegisteredProbe registered) {
        UnattendedAuthorization authorization = authorizer.authorize(registered.client(), scope);
        return new ShortcutOutcome(authorization, authorization.code()
                .map(code -> finding(ConsentShortcut.of(probe), registered, authorization, code)));
    }

    private ConsentFinding finding(ConsentShortcut shortcut, RegisteredProbe registered,
                                   UnattendedAuthorization authorization, IssuedCode code) {
        FindingDraft draft = new FindingDraft(server.authorizationEndpoint())
                .fact(SignedInFacts.registered(registered))
                .fact(SignedInFacts.issued(authorization, sessionSource))
                .evidence(authorization.exchanges());
        AuditIssueConfidence confidence = server.tokenEndpoint()
                .map(tokenEndpoint -> redeemed(tokenEndpoint, registered.client(), code, draft))
                .orElseGet(() -> unredeemable(draft));
        return draft.as(shortcut, confidence);
    }

    private static AuditIssueConfidence unredeemable(FindingDraft draft) {
        draft.fact(AuthorizationFacts.NO_TOKEN_ENDPOINT);
        return AuditIssueConfidence.FIRM;
    }

    private AuditIssueConfidence redeemed(URI tokenEndpoint, ProbeClient client, IssuedCode code,
                                          FindingDraft draft) {
        Redemption redemption = new CodeRedeemer(http, tokenEndpoint, server.resource(), client,
                tokens.ledgerFor(client)).redeem(code);
        redemption.exchange().ifPresent(exchange -> draft.evidence(List.of(exchange)));
        if (redemption.accessToken().isEmpty()) {
            draft.fact(AuthorizationFacts.unredeemed(redemption));
            return AuditIssueConfidence.FIRM;
        }
        AccessJudgement judgement = access.judge(redemption.accessToken().get());
        draft.fact(AuthorizationFacts.access(judgement)).evidence(judgement.evidence());
        return judgement.access() == Access.GRANTS_ACCESS ? AuditIssueConfidence.CERTAIN : AuditIssueConfidence.FIRM;
    }
}
