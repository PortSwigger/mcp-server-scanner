package com.mcpscanner.checks.catalog.oauthauthorizationconsent;

import com.mcpscanner.checks.api.BrowserConsentObservation;

final class SignedInFacts {

    static final String BROWSER_LIMITS = "The scanner cannot tell an automatic redirect from an Approve click "
            + "made within that time, so this is tentative. No HTTP evidence is attached: the browser sent the "
            + "requests.";
    static final String SCOPE_UNREADABLE = "The granted scope could not be read: ";

    private SignedInFacts() {
    }

    static String registered(RegisteredProbe probe) {
        return "The probe registered client_id " + probe.client().clientId() + " named \"" + probe.name()
                + "\" with redirect URI " + probe.client().callback() + ".";
    }

    static String issued(UnattendedAuthorization authorization, String sessionSource) {
        return "An authorization request carrying the signed-in session's cookies from " + sessionSource
                + " reached that redirect URI with an authorization code after " + authorization.redirectsFollowed()
                + " same-origin redirect(s), with no consent page on the way.";
    }

    static String scopeControl(String clientId, String granted, String sessionSource) {
        return "With the signed-in session's cookies from " + sessionSource + ", an authorization request for the "
                + "scanner's client_id " + clientId + " at its granted scope \"" + granted + "\" returned a code "
                + "with no consent page, so the server remembers that approval.";
    }

    static String scopeUpgrade(String requested, String extra) {
        return "The same request for scope \"" + requested + "\", adding \"" + extra + "\" which the user never "
                + "approved, also returned a code with no consent page.";
    }

    static String scopeGranted(String granted, boolean confidential) {
        return "Redeemed once as " + (confidential ? "the confidential client, authenticated with the client_secret "
                + "Connect used," : "a public client") + " with the scanner client's redirect URI and the probe's "
                + "PKCE verifier, the code returned an access token for scope \"" + granted + "\".";
    }

    static String observed(BrowserConsentObservation observation) {
        return "Right after the OAuth sign-in at Connect, the scanner opened the authorization URL for a client "
                + "named \"" + observation.clientName() + "\" with redirect URI " + observation.redirectUri()
                + " in your browser, and a code reached that redirect URI after "
                + observation.codeArrivedAfter().orElseThrow().toMillis() + " ms.";
    }

    static String freshNameControlMissing() {
        return "The fresh-name control was not tried or its client was not registered, so the server may skip "
                + "consent for any client rather than remembering it by name.";
    }

    static String freshNameControlTooLate(BrowserConsentObservation control) {
        return "The fresh-name control received a code after "
                + control.codeArrivedAfter().orElseThrow().toMillis() + " ms, too late to rule out an approval "
                + "click, so the server may skip consent for any client rather than remembering it by name.";
    }
}
