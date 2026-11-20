package com.mcpscanner.checks.catalog.oauthauthorizationconsent;

import com.mcpscanner.checks.api.SkipReason;

import java.net.URI;

final class SignedInSkips {

    static final SkipReason OPT_IN_OFF =
            SkipReason.notApplicable("the opt-in setting 'Test OAuth consent with my sign-in' is off");
    static final SkipReason SCANNER_CLIENT_UNKNOWN = SkipReason.prerequisiteMissing(
            "the scanner's own OAuth client is unknown: connect with OAuth");
    static final SkipReason NO_CLIENT_ISSUED =
            SkipReason.prerequisiteMissing("dynamic client registration did not issue a client_id");
    static final SkipReason SUBSUMED = SkipReason.notApplicable("subsumed: the authorization server already issued "
            + "a code without consent to a freshly named client on an unrelated host");

    private SignedInSkips() {
    }

    static SkipReason inconclusiveControl(String why) {
        return SkipReason.notApplicable("the fresh-client control was inconclusive: " + why);
    }

    static SkipReason foreignIssuer(URI scannerIssuer, URI probedIssuer) {
        return SkipReason.prerequisiteMissing("the scanner's own OAuth client was issued by " + scannerIssuer
                + ", not by " + probedIssuer + ", the authorization server under test");
    }

    static SkipReason plainHttpAuthorization(URI authorizationEndpoint) {
        return SkipReason.notApplicable("Burp's cookie jar cannot tell Secure cookies apart, so its cookies are not "
                + "sent to the plain-http authorization endpoint " + authorizationEndpoint);
    }

    static SkipReason splitOrigins(String why) {
        return SkipReason.notApplicable(why + ", so the signed-in session is not used: a code, verifier or token "
                + "obtained with it could reach a party other than the one that signed the user in");
    }

    static SkipReason noSession(String authorizationHost) {
        return SkipReason.prerequisiteMissing("no signed-in session for " + authorizationHost
                + ": sign in through Burp's browser or with OAuth at Connect");
    }
}
