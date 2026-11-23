package com.mcpscanner.signedin;

import com.mcpscanner.auth.oauth.BrowserLauncher;
import com.mcpscanner.auth.oauth.CallbackListener;
import com.mcpscanner.auth.oauth.CallbackListenerFactory;
import com.mcpscanner.auth.oauth.OAuthSignIn;
import com.mcpscanner.checks.api.BrowserConsentObservation;
import com.mcpscanner.checks.api.SignedInProbe;
import com.mcpscanner.checks.shared.oauth.AuthorizationParameters;
import com.mcpscanner.checks.shared.oauth.AuthorizationServer;
import com.mcpscanner.checks.shared.oauth.ClientMetadata;
import com.mcpscanner.checks.shared.oauth.Pkce;
import com.mcpscanner.checks.shared.oauth.ProbeCallback;
import com.mcpscanner.checks.shared.oauth.ProbeClientRegistrar;
import com.mcpscanner.checks.shared.oauth.RegisteredClient;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.net.URI;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

public final class BrowserConsentWalk {

    public static final Duration CODE_WAIT = Duration.ofSeconds(10);

    private static final int EPHEMERAL_PORT = 0;
    private static final String CALLBACK_PATH_PREFIX = "/consent-probe/";

    private final CallbackListenerFactory listeners;
    private final BrowserLauncher browser;
    private final Clock clock;
    private final Duration codeWait;
    private final BrowserConsentObservations observations;

    public BrowserConsentWalk(CallbackListenerFactory listeners, BrowserLauncher browser, Clock clock,
                              Duration codeWait, BrowserConsentObservations observations) {
        this.listeners = listeners;
        this.browser = browser;
        this.clock = clock;
        this.codeWait = codeWait;
        this.observations = observations;
    }

    Optional<BrowserConsentObservation> observe(SignedInProbe probe, String clientName, OAuthSignIn signIn,
                                                ProbeClientRegistrar registrar) {
        String path = CALLBACK_PATH_PREFIX + UUID.randomUUID();
        String host = ProbeCallback.hostUnrelatedTo(Optional.of(signIn.redirectUri()));
        try (CallbackListener listener = listeners.start(host, EPHEMERAL_PORT, path)) {
            URI redirectUri = URI.create("http://" + host + ":" + listener.port() + path);
            return registrar.registerAddingRefreshGrantIfRequired(
                            ClientMetadata.codeGrant(clientName, List.of(redirectUri.toString())))
                    .client()
                    .filter(client -> !Thread.currentThread().isInterrupted())
                    .map(client -> walk(probe, clientName, signIn, client, redirectUri, listener));
        } catch (IOException failure) {
            throw new UncheckedIOException("Could not listen for the probe client's callback", failure);
        }
    }

    private BrowserConsentObservation walk(SignedInProbe probe, String clientName, OAuthSignIn signIn,
                                           RegisteredClient client, URI redirectUri, CallbackListener listener) {
        String state = UUID.randomUUID().toString();
        URI authorizationUrl = AuthorizationParameters.withQuery(signIn.authorizationEndpoint(),
                AuthorizationParameters.of(server(signIn), "code", client.clientId(), redirectUri, state,
                        Pkce.generate()));
        Instant opened = clock.instant();
        browser.open(authorizationUrl);
        Optional<Duration> codeArrivedAfter = new CallbackWait(listener, state, codeWait).codeArrived()
                ? Optional.of(Duration.between(opened, clock.instant()))
                : Optional.empty();
        BrowserConsentObservation observation = new BrowserConsentObservation(probe, signIn.authorizationEndpoint(),
                clientName, redirectUri, codeArrivedAfter);
        observations.record(observation);
        return observation;
    }

    private static AuthorizationServer server(OAuthSignIn signIn) {
        Optional<String> scope = signIn.grantedScopes().isEmpty()
                ? Optional.empty()
                : Optional.of(String.join(" ", signIn.grantedScopes()));
        return new AuthorizationServer(signIn.issuer(), signIn.authorizationEndpoint(), signIn.registrationEndpoint(),
                Optional.empty(), Optional.empty(), signIn.resource(), scope, List.copyOf(signIn.grantedScopes()));
    }
}
