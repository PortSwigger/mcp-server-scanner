package com.mcpscanner.auth.oauth;

import burp.api.montoya.http.Http;
import com.mcpscanner.auth.oauth.safety.SuspiciousDestinationGate;
import com.mcpscanner.config.ClientIdentity;
import com.mcpscanner.config.ClientIdentityField;
import com.mcpscanner.config.ClientIdentityProvider;
import com.mcpscanner.logging.McpEventLog;
import com.nimbusds.oauth2.sdk.as.AuthorizationServerMetadata;

import java.io.IOException;
import java.net.URI;
import java.time.Clock;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.function.Supplier;

public class OAuthAuthorizationFlow {

    private final CallbackListenerFactory listenerFactory;
    private final McpEventLog eventLog;
    private final IssuerMetadataResolver metadataResolver;
    private final ClientRegistrar clientRegistrar;
    private final BrowserAuthorizationSessions sessions;
    private final ClientIdentityProvider identityProvider;
    private final List<SignInListener> signInListeners = new CopyOnWriteArrayList<>();

    public OAuthAuthorizationFlow(CallbackListenerFactory listenerFactory,
                                   BrowserLauncher browserLauncher,
                                   Clock clock,
                                   SuspiciousDestinationGate gate,
                                   McpEventLog eventLog,
                                   Http http) {
        this(listenerFactory, browserLauncher, clock, gate, eventLog, http,
                ClientIdentityProvider.defaults());
    }

    public OAuthAuthorizationFlow(CallbackListenerFactory listenerFactory,
                                   BrowserLauncher browserLauncher,
                                   Clock clock,
                                   SuspiciousDestinationGate gate,
                                   McpEventLog eventLog,
                                   Http http,
                                   ClientIdentityProvider identityProvider) {
        McpEventLog log = eventLog != null ? eventLog : McpEventLog.noop();
        BurpHttpRequestSender sender = new BurpHttpRequestSender(Objects.requireNonNull(http, "http must not be null"));
        OAuthDestinationGuard guard = new OAuthDestinationGuard(gate, log);
        this.listenerFactory = listenerFactory;
        this.eventLog = log;
        this.identityProvider = identityProvider;
        this.metadataResolver = new IssuerMetadataResolver(new BurpMetadataClient(sender), guard, log);
        this.clientRegistrar = new ClientRegistrar(sender, guard, identityProvider, log);
        this.sessions = new BrowserAuthorizationSessions(listenerFactory, browserLauncher,
                new TokenEndpointClient(sender, gate), clock, log);
    }

    public OAuthSession connect(URI mcpResource, OAuthClientHints hints) {
        return connect(mcpResource, hints, null);
    }

    public OAuthSession connect(URI mcpResource, OAuthClientHints hints,
                                AuthorizationServerMetadata preDiscovered) {
        eventLog.info("OAuth flow starting - issuer=" + hints.issuer()
                + ", dcr=" + (hints.allowDcr() && hints.clientId() == null ? "yes" : "no"));
        try (CallbackListener listener = listenerFactory.start(hints.redirectPort(), LoopbackCallback.PATH)) {
            LoopbackCallback callback = new LoopbackCallback(listener.port());
            AuthorizationServerMetadata metadata = metadataResolver.resolve(hints.issuer(), mcpResource, preDiscovered);
            ClientRegistration client = clientRegistrar.register(metadata, hints, callback, mcpResource);
            SharedOAuthSession session = sessions.open(mcpResource, hints, metadata, client, listener, callback);
            OAuthTokens tokens = authenticate(session);
            notifySignedIn(() -> signIn(mcpResource, metadata, client, callback, session), session);
            return new OAuthSession(tokens, client.clientId(), client.clientSecret(),
                    client.registrationAccessToken(), client.registrationClientUri(), session,
                    client.registrationMode(), Optional.ofNullable(metadata.getRegistrationEndpointURI()));
        } catch (IOException e) {
            throw new OAuthException("Failed to start callback listener on port " + hints.redirectPort()
                    + ": " + e.getMessage(), e);
        }
    }

    public void addSignInListener(SignInListener listener) {
        signInListeners.add(Objects.requireNonNull(listener, "listener must not be null"));
    }

    private OAuthSignIn signIn(URI mcpResource, AuthorizationServerMetadata metadata, ClientRegistration client,
                               LoopbackCallback callback, SharedOAuthSession session) {
        ClientIdentity identity = identityProvider.current();
        String softwareId = identity.value(ClientIdentityField.SOFTWARE_ID);
        return new OAuthSignIn(URI.create(metadata.getIssuer().getValue()), metadata.getAuthorizationEndpointURI(),
                Optional.ofNullable(metadata.getRegistrationEndpointURI()), client.clientId(),
                client.clientName(), callback.uri(), session.grantedScopes(),
                softwareId.isEmpty() ? Optional.empty() : Optional.of(softwareId), mcpResource,
                Optional.ofNullable(client.clientSecret()).filter(secret -> !secret.isBlank()));
    }

    private void notifySignedIn(Supplier<OAuthSignIn> signIn, SharedOAuthSession session) {
        if (signInListeners.isEmpty()) {
            return;
        }
        try {
            OAuthSignIn completed = signIn.get();
            signInListeners.forEach(listener -> listener.signedIn(completed));
            session.onGrantWidened(granted -> notifyScopesWidened(completed.withGrantedScopes(granted)));
        } catch (RuntimeException failure) {
            eventLog.warn("Sign-in listener failed: " + failure.getMessage());
        }
    }

    private void notifyScopesWidened(OAuthSignIn widened) {
        try {
            signInListeners.forEach(listener -> listener.scopesWidened(widened));
        } catch (RuntimeException failure) {
            eventLog.warn("Sign-in listener failed: " + failure.getMessage());
        }
    }

    private OAuthTokens authenticate(SharedOAuthSession session) {
        try {
            OAuthTokens tokens = session.authenticate();
            eventLog.info("Token exchange succeeded");
            session.scopeGrant().withheldWarning().ifPresent(eventLog::warn);
            return tokens;
        } catch (OAuthException failure) {
            eventLog.error("OAuth callback rejected or token exchange failed: " + failure.getMessage());
            throw failure;
        }
    }
}
