package com.mcpscanner.auth.oauth;

import com.mcpscanner.auth.grant.IssuedTokens;
import com.nimbusds.jwt.JWTParser;
import com.nimbusds.oauth2.sdk.token.BearerAccessToken;
import com.nimbusds.oauth2.sdk.token.RefreshToken;
import com.mcpscanner.core.oauth.AuthorizationCodeConfig;
import com.mcpscanner.core.oauth.BrowserAuthorization;
import com.mcpscanner.core.oauth.CallbackValidationException;
import com.mcpscanner.core.oauth.OAuthCredential;
import com.mcpscanner.core.oauth.OAuthFlowEngine;
import com.mcpscanner.core.oauth.OAuthFlowException;
import com.mcpscanner.core.oauth.TokenExchange;

import java.time.Clock;
import java.time.Instant;
import java.util.Optional;
import java.util.concurrent.locks.ReentrantLock;
import java.util.function.Supplier;

public final class SharedOAuthSession {
    private AuthorizationCodeConfig config;
    private final TokenExchange exchange;
    private final BrowserAuthorization browser;
    private final OAuthFlowEngine engine;
    private final Clock clock;
    private final InMemoryCredentialStore credentials = new InMemoryCredentialStore();
    private final ReentrantLock flowLock = new ReentrantLock();
    private final Object publication = new Object();
    private final SignInEvidence signInEvidence;
    private final java.util.List<java.util.function.Consumer<java.util.Set<String>>> grantListeners =
            new java.util.concurrent.CopyOnWriteArrayList<>();

    SharedOAuthSession(AuthorizationCodeConfig config, TokenExchange exchange,
                       BrowserAuthorization browser, Clock clock) {
        this(config, exchange, browser, clock, SignInEvidence.none());
    }

    SharedOAuthSession(AuthorizationCodeConfig config, TokenExchange exchange,
                       BrowserAuthorization browser, Clock clock, SignInEvidence signInEvidence) {
        this.signInEvidence = signInEvidence;
        this.config = config;
        this.exchange = exchange;
        this.browser = browser;
        this.clock = clock;
        this.engine = new OAuthFlowEngine(exchange, browser, credentials, clock);
    }

    public SignInEvidence signInEvidence() {
        return signInEvidence;
    }

    OAuthTokens authenticate() {
        try {
            return tokens(engine.authenticate(publishedConfig()));
        } catch (CallbackValidationException failure) {
            throw callbackFailure(failure);
        } catch (OAuthFlowException failure) {
            throw new OAuthException(failure.getMessage());
        }
    }

    public OAuthTokens reauthorize() {
        return exclusively(this::authenticate);
    }

    public OAuthTokens refresh() {
        return exclusively(() -> {
            try {
                return tokens(engine.refresh(publishedConfig()));
            } catch (OAuthFlowException failure) {
                throw new OAuthException(failure.getMessage());
            }
        });
    }

    public com.mcpscanner.core.connection.CredentialProvider credentialProvider(Runnable refresh,
            java.util.function.Function<java.util.Set<String>, com.mcpscanner.core.oauth.AuthorizationApproval> approval,
            java.util.function.Consumer<OAuthTokens> onAuthorized) {
        return new com.mcpscanner.core.connection.OAuthCredentialProvider(publishedConfig().binding(),
                new com.mcpscanner.core.connection.OAuthCredentialAccess() {
                    @Override
                    public Optional<OAuthCredential> current() {
                        return currentCredential();
                    }

                    @Override
                    public boolean refreshAvailable() {
                        return current().map(value -> value.refreshToken() != null).orElse(false);
                    }

                    @Override
                    public void refresh() {
                        refresh.run();
                    }

                    @Override
                    public void authorize(java.util.Set<String> scopes) {
                        onAuthorized.accept(SharedOAuthSession.this.authorize(scopes));
                    }
                }, approval);
    }

    public void onGrantWidened(java.util.function.Consumer<java.util.Set<String>> listener) {
        grantListeners.add(java.util.Objects.requireNonNull(listener, "listener must not be null"));
    }

    public java.util.Set<String> requestedScopes() {
        return publishedConfig().scopes();
    }

    public java.util.Set<String> grantedScopes() {
        return currentCredential().map(OAuthCredential::grantedScopes).orElse(java.util.Set.of());
    }

    public ScopeGrant scopeGrant() {
        return new ScopeGrant(requestedScopes(), grantedScopes());
    }

    public AuthorizationCodeConfig configuration() {
        return publishedConfig();
    }

    public void adopt(IssuedTokens issued) {
        exclusively(() -> tokens(replaceCredential(issued)));
    }

    private OAuthCredential replaceCredential(IssuedTokens issued) {
        synchronized (publication) {
            OAuthCredential current = credentials.load(config.binding())
                    .orElseThrow(() -> new OAuthException("No OAuth credential available to replace"));
            OAuthCredential replacement = new OAuthCredential(config.binding(), issued.accessToken(),
                    issued.refreshToken().orElse(current.refreshToken()), clock.instant().plus(issued.lifetime()),
                    current.grantedScopes());
            credentials.save(config.binding(), replacement);
            return replacement;
        }
    }

    public OAuthTokens currentTokens() {
        return tokens(currentCredential()
                .orElseThrow(() -> new OAuthException("No OAuth credential available; reconnect to re-authorize")));
    }

    private Optional<OAuthCredential> currentCredential() {
        synchronized (publication) {
            return credentials.load(config.binding());
        }
    }

    private AuthorizationCodeConfig publishedConfig() {
        synchronized (publication) {
            return config;
        }
    }

    private void publish(AuthorizationCodeConfig next, OAuthCredential credential) {
        synchronized (publication) {
            credentials.save(next.binding(), credential);
            config = next;
        }
    }

    private OAuthTokens authorize(java.util.Set<String> scopes) {
        return exclusively(() -> authorizeExpanded(scopes));
    }

    private OAuthTokens authorizeExpanded(java.util.Set<String> scopes) {
        AuthorizationCodeConfig next = expandedConfig(scopes);
        try {
            OAuthCredential credential = new OAuthFlowEngine(exchange, browser, new InMemoryCredentialStore(), clock)
                    .authenticate(next);
            publish(next, credential);
            grantListeners.forEach(listener -> listener.accept(credential.grantedScopes()));
            return tokens(credential);
        } catch (CallbackValidationException failure) {
            throw callbackFailure(failure);
        } catch (OAuthFlowException failure) {
            throw new OAuthException(failure.getMessage() + "; reconnect to authorize the required scopes");
        }
    }

    private AuthorizationCodeConfig expandedConfig(java.util.Set<String> scopes) {
        AuthorizationCodeConfig current = publishedConfig();
        var expanded = new java.util.HashSet<>(current.scopes());
        currentCredential().ifPresent(credential -> expanded.addAll(credential.grantedScopes()));
        expanded.addAll(scopes);
        return new AuthorizationCodeConfig(current.issuer(), current.resource(), current.authorizationEndpoint(),
                current.tokenEndpoint(), current.client(), current.callbackUri(), expanded,
                current.issuerParameterSupported());
    }

    private OAuthTokens exclusively(Supplier<OAuthTokens> flowStep) {
        flowLock.lock();
        try {
            return flowStep.get();
        } finally {
            flowLock.unlock();
        }
    }

    private OAuthException callbackFailure(CallbackValidationException failure) {
        String reason = switch (failure.reason()) {
            case STATE_MISMATCH -> "state mismatch (possible CSRF)";
            case MISSING_ISSUER -> "missing issuer";
            case ISSUER_MISMATCH -> "issuer mismatch";
        };
        return new OAuthException("OAuth callback " + reason);
    }

    private OAuthTokens tokens(OAuthCredential credential) {
        Instant expiry = credential.expiresAt() != null ? credential.expiresAt() : clock.instant().plusSeconds(300);
        return new OAuthTokens(new BearerAccessToken(credential.accessToken()),
                credential.refreshToken() != null ? new RefreshToken(credential.refreshToken()) : null,
                expiry, subject(credential.accessToken()));
    }

    private String subject(String accessToken) {
        try {
            return JWTParser.parse(accessToken).getJWTClaimsSet().getSubject();
        } catch (java.text.ParseException | RuntimeException ignored) {
            return null;
        }
    }
}
