package com.mcpscanner.signedin;

import com.mcpscanner.auth.oauth.OAuthSignIn;
import com.mcpscanner.auth.oauth.SignInListener;
import com.mcpscanner.client.PrimaryConnection;

import java.util.Optional;

public final class ConnectSignIns implements SignInListener {

    private OAuthSignIn pending;
    private OAuthSignIn current;

    @Override
    public synchronized void signedIn(OAuthSignIn signIn) {
        pending = signIn;
    }

    @Override
    public synchronized void scopesWidened(OAuthSignIn widened) {
        pending = widenedIfSameClient(pending, widened);
        current = widenedIfSameClient(current, widened);
    }

    public synchronized void connectAttemptStarted() {
        forget();
    }

    public synchronized void connected(PrimaryConnection connection) {
        current = Optional.ofNullable(pending)
                .filter(signIn -> McpResourceMatch.sameResource(signIn.resource(), connection.endpoint()))
                .orElse(null);
        pending = null;
    }

    public synchronized void disconnected() {
        current = null;
    }

    public synchronized void forget() {
        pending = null;
        current = null;
    }

    private static OAuthSignIn widenedIfSameClient(OAuthSignIn known, OAuthSignIn widened) {
        return known != null && known.sameClientAs(widened) ? widened : known;
    }

    public synchronized Optional<OAuthSignIn> current() {
        return Optional.ofNullable(current);
    }
}
