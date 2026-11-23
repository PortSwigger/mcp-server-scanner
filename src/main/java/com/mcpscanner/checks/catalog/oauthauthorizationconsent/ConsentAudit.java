package com.mcpscanner.checks.catalog.oauthauthorizationconsent;

import burp.api.montoya.http.message.HttpRequestResponse;
import com.mcpscanner.checks.api.OAuthSkipLog;
import com.mcpscanner.checks.api.SkipReason;
import com.mcpscanner.checks.shared.oauth.AuthorizationServer;
import com.mcpscanner.checks.shared.oauth.OAuthHttp;

import java.util.ArrayList;
import java.util.List;

final class ConsentAudit {

    private final AuthorizationServer server;
    private final OAuthHttp http;
    private final UnattendedAuthorizer authorizer;
    private final TokenAccess access;
    private final TokenLedger ledger;
    private final OAuthSkipLog skips;
    private final String redemptionTests;

    ConsentAudit(AuthorizationServer server, OAuthHttp http, UnattendedAuthorizer authorizer, TokenAccess access,
                 TokenLedger ledger, OAuthSkipLog skips, String mcpEndpoint) {
        this.server = server;
        this.http = http;
        this.authorizer = authorizer;
        this.access = access;
        this.ledger = ledger;
        this.skips = skips;
        this.redemptionTests = "the code redemption and reuse tests for " + mcpEndpoint;
    }

    List<ConsentFinding> run(ProbeClient client) {
        UnattendedAuthorization authorization = authorizer.authorize(client);
        if (authorization.code().isEmpty()) {
            skips.notRun(redemptionTests, noCodeReason(authorization));
            return List.of();
        }
        return codeFindings(client, authorization, authorization.code().get());
    }

    private static SkipReason noCodeReason(UnattendedAuthorization authorization) {
        return authorization.hopLimitReached()
                ? SkipReason.budgetExhausted("the authorization redirects exceeded "
                        + UnattendedAuthorizer.MAX_REDIRECTS + " hops")
                : SkipReason.notApplicable("the authorization endpoint issued no code without login or consent");
    }

    private List<ConsentFinding> codeFindings(ProbeClient client, UnattendedAuthorization authorization,
                                              IssuedCode code) {
        FindingDraft draft = new FindingDraft(server.authorizationEndpoint())
                .fact(AuthorizationFacts.issued(authorization))
                .evidence(authorization.exchanges());
        authorization.sessionCreatedBy().ifPresent(page -> draft.fact(AuthorizationFacts.sessionCreatedBy(page)));
        boolean sessionCreated = authorization.sessionCreatedBy().isPresent();
        return server.tokenEndpoint()
                .map(tokenEndpoint -> redeemed(new CodeRedeemer(http, tokenEndpoint, server.resource(), client, ledger),
                        client, code, draft, sessionCreated))
                .orElseGet(() -> unredeemable(draft, sessionCreated));
    }

    private List<ConsentFinding> unredeemable(FindingDraft draft, boolean sessionCreated) {
        skips.notRun(redemptionTests,
                SkipReason.prerequisiteMissing("the authorization server advertises no token endpoint"));
        return List.of(draft.fact(AuthorizationFacts.NO_TOKEN_ENDPOINT).as(unredeemedKind(sessionCreated)));
    }

    private List<ConsentFinding> redeemed(CodeRedeemer redeemer, ProbeClient client, IssuedCode code,
                                          FindingDraft draft, boolean sessionCreated) {
        Redemption redemption = redeemer.redeem(code);
        return redemption.accessToken()
                .map(token -> judged(redeemer, client, code, redemption, draft, sessionCreated))
                .orElseGet(() -> List.of(draft.fact(AuthorizationFacts.unredeemed(redemption))
                        .fact(AuthorizationFacts.REDEMPTION_NOT_ATTACHED).as(unredeemedKind(sessionCreated))));
    }

    private List<ConsentFinding> judged(CodeRedeemer redeemer, ProbeClient client, IssuedCode code,
                                        Redemption redemption, FindingDraft draft, boolean sessionCreated) {
        AccessJudgement judgement = access.judge(redemption.accessToken().orElseThrow());
        FindingKind kind = FindingKind.forAccess(judgement.access(), sessionCreated);
        draft.fact(AuthorizationFacts.access(judgement));
        if (kind.attachesTokenUse()) {
            draft.evidence(tokenUse(redemption, judgement));
        } else {
            draft.fact(AuthorizationFacts.ONLY_TRAIL_ATTACHED);
        }
        List<ConsentFinding> findings = new ArrayList<>();
        findings.add(draft.as(kind));
        if (judgement.access() == Access.GRANTS_ACCESS) {
            new CodeReuseProbe(authorizer, redeemer, access).probe(client, code, redemption)
                    .ifPresent(findings::add);
        }
        return findings;
    }

    private static List<HttpRequestResponse> tokenUse(Redemption redemption, AccessJudgement judgement) {
        List<HttpRequestResponse> exchanges = new ArrayList<>();
        redemption.exchange().ifPresent(exchanges::add);
        exchanges.addAll(judgement.evidence());
        return exchanges;
    }

    private static FindingKind unredeemedKind(boolean sessionCreated) {
        return FindingKind.forAccess(Access.NOT_SHOWN, sessionCreated);
    }
}
