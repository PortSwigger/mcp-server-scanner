package com.mcpscanner;

import com.mcpscanner.identity.credentials.IdentityCredentialServices;
import com.mcpscanner.identity.credentials.OAuthIdentitySignIn;
import com.mcpscanner.identity.credentials.SharedAuthSettings;
import com.mcpscanner.identity.credentials.ScopeApprovals;

import java.net.URI;
import java.time.Clock;
import java.util.concurrent.ExecutorService;

final class IdentityWiring {

    private final ExtensionFoundation foundation;
    private final OAuthWiring oauth;
    private final ExecutorService signInWorker;

    private IdentityWiring(ExtensionFoundation foundation, OAuthWiring oauth, ExecutorService signInWorker) {
        this.foundation = foundation;
        this.oauth = oauth;
        this.signInWorker = signInWorker;
    }

    static IdentityWiring create(ExtensionFoundation foundation, OAuthWiring oauth) {
        foundation.configStore().addEndpointChangeListener(foundation.toolCallRefusals()::clear);
        return new IdentityWiring(foundation, oauth, DaemonWorkers.single("mcp-identity-sign-in"));
    }

    IdentityCredentialServices credentialServices(SharedAuthSettings sharedOAuthClient,
                                                  ScopeApprovals scopeApprovals) {
        OAuthIdentitySignIn signIn = new OAuthIdentitySignIn(oauth.identitySignInFlow(),
                () -> URI.create(foundation.configStore().endpoint()), oauth.discoverer()::discover, scopeApprovals,
                Clock.systemUTC(),
                foundation.eventLog(), oauth.authorizationGate()::reset);
        return IdentityCredentialServices.create(foundation.identities(), sharedOAuthClient, signIn, signInWorker,
                foundation.eventLog());
    }

    void addShutdownHooks(ShutdownHooks shutdown) {
        shutdown.add("Identity sign-in", signInWorker::shutdownNow);
        shutdown.add("Identity credentials", foundation.identities()::clearCredentials);
    }
}
