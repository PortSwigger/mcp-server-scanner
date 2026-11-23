package com.mcpscanner.checks.catalog.oauthauthorizationconsent;

import java.net.URI;

final class AuthorizationFacts {

    static final String NO_TOKEN_ENDPOINT =
            "The authorization server advertises no token endpoint, so the code was not redeemed.";

    static final String ONLY_TRAIL_ATTACHED = "The redemption and tools/list requests are not attached; the "
            + "evidence is the authorization redirect trail.";
    static final String REDEMPTION_NOT_ATTACHED = "The redemption is not attached; the evidence is the "
            + "authorization redirect trail.";

    private AuthorizationFacts() {
    }

    static String issued(UnattendedAuthorization authorization) {
        return "An authorization request sent with no session cookie or credential reached the probe client's "
                + "callback with an authorization code after " + authorization.redirectsFollowed()
                + " same-origin redirect(s), with no login form or consent page on the way.";
    }

    static String sessionCreatedBy(URI page) {
        return "The server created a session for the anonymous visitor at " + page
                + " (Set-Cookie) and the code was issued to that session.";
    }

    static String unredeemed(Redemption redemption) {
        return "The token endpoint issued no access token for the code (" + redemption.status() + ").";
    }

    static String access(AccessJudgement judgement) {
        return switch (judgement.access()) {
            case GRANTS_ACCESS -> "The code redeemed to an access token. tools/list was refused without a token ("
                    + judgement.anonymousStatus() + ") and succeeded with it (" + judgement.tokenStatus() + ").";
            case ALREADY_OPEN -> "The code redeemed to an access token, but tools/list already succeeded without "
                    + "any token (" + judgement.anonymousStatus() + ").";
            case NOT_SHOWN -> "The code redeemed to an access token, but it did not turn a refused tools/list into "
                    + "a success (" + judgement.anonymousStatus() + " without a token, " + judgement.tokenStatus()
                    + " with it).";
        };
    }
}
