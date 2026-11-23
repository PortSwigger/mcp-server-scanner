package com.mcpscanner.checks.catalog.oauthauthorizationconsent;

import burp.api.montoya.http.message.HttpRequestResponse;

import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

final class CodeReuseProbe {

    static final int CONCURRENT_REDEMPTIONS = 5;

    private final UnattendedAuthorizer authorizer;
    private final CodeRedeemer redeemer;
    private final TokenAccess access;

    CodeReuseProbe(UnattendedAuthorizer authorizer, CodeRedeemer redeemer, TokenAccess access) {
        this.authorizer = authorizer;
        this.redeemer = redeemer;
        this.access = access;
    }

    Optional<ConsentFinding> probe(ProbeClient client, IssuedCode redeemedCode, Redemption first) {
        return sequentialReuse(redeemedCode, first).or(() -> concurrentReuse(client));
    }

    private Optional<ConsentFinding> sequentialReuse(IssuedCode redeemedCode, Redemption first) {
        Redemption replay = redeemer.redeem(redeemedCode);
        String returned = replay.accessToken().equals(first.accessToken())
                ? "the same access token again" : "a new access token";
        return working(replay).map(judgement -> finding(
                "A sequential second redemption of the already redeemed code returned " + returned
                        + ", and that token answered tools/list (" + judgement.anonymousStatus()
                        + " without a token, " + judgement.tokenStatus() + " with it).",
                List.of(first, replay), judgement));
    }

    private Optional<ConsentFinding> concurrentReuse(ProbeClient client) {
        Optional<IssuedCode> fresh = authorizer.authorize(client).code();
        if (fresh.isEmpty()) {
            return Optional.empty();
        }
        List<Redemption> issued = redeemer.redeemConcurrently(fresh.get(), CONCURRENT_REDEMPTIONS).stream()
                .filter(redemption -> redemption.accessToken().isPresent())
                .toList();
        if (issued.size() < 2) {
            return Optional.empty();
        }
        List<WorkingToken> working = issued.stream()
                .flatMap(redemption -> working(redemption).map(judgement -> new WorkingToken(redemption, judgement))
                        .stream())
                .limit(2)
                .toList();
        if (working.size() < 2) {
            return Optional.empty();
        }
        AccessJudgement second = working.get(1).judgement();
        return Optional.of(finding(
                CONCURRENT_REDEMPTIONS + " concurrent redemptions of one fresh code returned " + issued.size()
                        + " access tokens, and at least two of them answered tools/list ("
                        + second.anonymousStatus() + " without a token, " + second.tokenStatus()
                        + " with the second).",
                working.stream().map(WorkingToken::redemption).toList(), second));
    }

    private Optional<AccessJudgement> working(Redemption redemption) {
        return redemption.accessToken().map(access::judge)
                .filter(judgement -> judgement.access() == Access.GRANTS_ACCESS);
    }

    private ConsentFinding finding(String fact, List<Redemption> redemptions, AccessJudgement judgement) {
        List<HttpRequestResponse> evidence = new ArrayList<>();
        redemptions.forEach(redemption -> redemption.exchange().ifPresent(evidence::add));
        evidence.addAll(judgement.evidence());
        return new FindingDraft(redeemer.tokenEndpoint()).fact(fact).evidence(evidence).as(FindingKind.CODE_REUSE);
    }
}
