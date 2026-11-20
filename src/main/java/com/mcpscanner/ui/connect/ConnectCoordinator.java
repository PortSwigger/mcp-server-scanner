package com.mcpscanner.ui.connect;

import com.mcpscanner.config.AuthTypeNames;
import com.mcpscanner.auth.AuthStrategy;
import com.mcpscanner.auth.NoAuthStrategy;
import com.mcpscanner.auth.OAuthAuthCodeStrategy;
import com.mcpscanner.auth.grants.OptionalGrantSettings;
import com.mcpscanner.auth.oauth.OAuthClientHints;
import com.mcpscanner.auth.oauth.discovery.AuthRequirement;
import com.mcpscanner.auth.oauth.discovery.DiscoveredMetadata;
import com.mcpscanner.client.ConnectResult;
import com.nimbusds.oauth2.sdk.as.AuthorizationServerMetadata;
import com.mcpscanner.client.McpClientManager;
import com.mcpscanner.client.McpServerConfig;
import com.mcpscanner.identity.credentials.CredentialNeed;
import com.mcpscanner.identity.credentials.CredentialNeedException;
import com.mcpscanner.logging.McpEventLog;
import com.mcpscanner.scan.request.AdvertisedAuthorizationServer;
import com.mcpscanner.ui.OAuthConnectSupport;
import com.mcpscanner.ui.state.ConnectAttempt;
import com.mcpscanner.ui.state.ConnectPhase;

import java.net.URI;
import java.util.Objects;
import java.util.function.BiFunction;

public final class ConnectCoordinator {

    public static final BiFunction<URI, OptionalGrantSettings, AuthStrategy> NO_OPTIONAL_GRANTS =
            (endpoint, settings) -> {
                throw new IllegalStateException("Client credentials and enterprise-managed OAuth are not configured");
            };

    private final BiFunction<URI, OptionalGrantSettings, AuthStrategy> optionalGrants;
    private final OAuthConnectSupport support;
    private final McpClientManager clientManager;
    private final McpEventLog eventLog;

    public ConnectCoordinator(OAuthConnectSupport support, McpClientManager clientManager, McpEventLog eventLog) {
        this(support, clientManager, eventLog, NO_OPTIONAL_GRANTS);
    }

    public ConnectCoordinator(OAuthConnectSupport support, McpClientManager clientManager, McpEventLog eventLog,
                              BiFunction<URI, OptionalGrantSettings, AuthStrategy> optionalGrants) {
        this.optionalGrants = Objects.requireNonNull(optionalGrants);
        this.support = Objects.requireNonNull(support, "support must not be null");
        this.clientManager = Objects.requireNonNull(clientManager, "clientManager must not be null");
        this.eventLog = Objects.requireNonNull(eventLog, "eventLog must not be null");
    }

    public ConnectionAttemptResult connect(ConnectAttempt attempt,
                                           ProgressReporter progress,
                                           Runnable terminalFailureCallback) {
        clientManager.beginConnectAttempt();
        support.beginSignInAttempt();
        if (AuthTypeNames.AUTO.equals(attempt.authType())) {
            return connectAutomatically(attempt, progress, terminalFailureCallback);
        }
        AuthStrategy resolved = attempt.snapshotAuth();
        reportTerminalFailures(resolved, terminalFailureCallback);
        OAuthOutcome oauth = OAuthOutcome.NONE;
        if (AuthTypeNames.OAUTH.equals(attempt.authType()) && !attempt.isOptionalGrant() && resolved == null) {
            oauth = completeOAuth(attempt, progress, terminalFailureCallback, null);
            resolved = oauth.strategy();
        }
        if (attempt.isOptionalGrant()) {
            progress.report(ConnectPhase.OAUTH, "Checking the authorization server and requesting a token…");
            resolved = Objects.requireNonNull(optionalGrants.apply(URI.create(attempt.endpoint()),
                    attempt.optionalGrantSettings()), "The OAuth grant did not return an access token");
        }
        return connectWith(attempt, resolved, oauth, null);
    }

    private static void reportTerminalFailures(AuthStrategy savedSession, Runnable terminalFailureCallback) {
        if (savedSession != null) {
            savedSession.setTerminalFailureListener(terminalFailureCallback);
        }
    }

    private ConnectionAttemptResult connectAutomatically(ConnectAttempt attempt,
                                                         ProgressReporter progress,
                                                         Runnable terminalFailureCallback) {
        progress.report(ConnectPhase.DISCOVER, "Checking whether the server needs authentication…");
        AuthRequirement requirement = support.probeAuthRequirement(attempt.endpoint(), attempt.transport());
        if (requirement instanceof AuthRequirement.OAuth oauth) {
            return connectAutomaticallyWithOAuth(attempt, progress, terminalFailureCallback, oauth.metadata());
        }
        if (requirement instanceof AuthRequirement.CredentialsRequired required) {
            throw new CredentialNeedException(required.answer(),
                    new CredentialNeed.ServerRefused(required.answer(), required.bearerExpected()));
        }
        if (requirement instanceof AuthRequirement.Unsupported unsupported) {
            throw new IllegalStateException(unsupported.reason());
        }
        return connectWith(attempt, new NoAuthStrategy(), OAuthOutcome.NONE, announceResolution(AutoAuthLabel.noAuth()));
    }

    private ConnectionAttemptResult connectAutomaticallyWithOAuth(ConnectAttempt attempt,
                                                                  ProgressReporter progress,
                                                                  Runnable terminalFailureCallback,
                                                                  DiscoveredMetadata discovered) {
        requireUsableOAuthSettings(attempt);
        support.applyDiscoveredMetadata(discovered);
        OAuthOutcome oauth = completeOAuth(attempt, progress, terminalFailureCallback, discovered);
        String label = announceResolution(AutoAuthLabel.oauth(oauth.strategy().registrationMode()));
        return connectWith(attempt, oauth.strategy(), oauth, label);
    }

    private static void requireUsableOAuthSettings(ConnectAttempt attempt) {
        if (attempt.oauthHints() == null) {
            throw new CredentialNeedException(
                    "The server uses OAuth, but the OAuth client in the Client tab is incomplete: " + attempt.oauthSettingsError(),
                    new CredentialNeed.OAuthSignInIncomplete(attempt.oauthSettingsError()));
        }
    }

    private String announceResolution(String label) {
        eventLog.info("Auth: " + label);
        return label;
    }

    private OAuthOutcome completeOAuth(ConnectAttempt attempt,
                                                ProgressReporter progress,
                                                Runnable terminalFailureCallback,
                                                DiscoveredMetadata alreadyDiscovered) {
        OAuthClientHints hints = attempt.oauthHints();
        DiscoveredMetadata discovered = alreadyDiscovered;
        if (discovered == null && hints.issuer() == null) {
            progress.report(ConnectPhase.DISCOVER, "Discovering OAuth metadata…");
            discovered = support.discoverOauthMetadataSync(attempt.endpoint());
            support.applyDiscoveredMetadata(discovered);
        }
        if (discovered != null) {
            hints = withDiscovered(hints, discovered);
        }
        progress.report(ConnectPhase.OAUTH, signInMessage(hints));
        AuthorizationServerMetadata preDiscovered = discovered != null ? discovered.asMetadata() : null;
        OAuthAuthCodeStrategy strategy = support.completeOAuthDance(hints, attempt.mcpResource(), eventLog, preDiscovered);
        strategy.setTerminalFailureListener(terminalFailureCallback);
        progress.report(ConnectPhase.CONNECT, "Listing tools…");
        return new OAuthOutcome(strategy, discovered != null
                ? DiscoveredAuthorizationServer.of(discovered) : support.authorizationServerOfLastDance());
    }

    private ConnectionAttemptResult connectWith(ConnectAttempt attempt, AuthStrategy resolved,
                                                OAuthOutcome oauth, String autoResolution) {
        McpServerConfig cfg = new McpServerConfig(attempt.endpoint(), attempt.transport(), resolved);
        ConnectResult result = clientManager.connect(cfg);
        return new ConnectionAttemptResult(result, oauth.strategy(), resolved, autoResolution,
                oauth.authorizationServer());
    }

    private record OAuthOutcome(OAuthAuthCodeStrategy strategy, AdvertisedAuthorizationServer authorizationServer) {
        static final OAuthOutcome NONE = new OAuthOutcome(null, AdvertisedAuthorizationServer.none());
    }

    private static String signInMessage(OAuthClientHints hints) {
        return "Waiting for browser sign-in (times out in " + hints.timeout().toMinutes() + " min)…";
    }

    private static OAuthClientHints withDiscovered(OAuthClientHints base, DiscoveredMetadata discovered) {
        Objects.requireNonNull(discovered.issuer(), "discovered issuer must not be null");
        return base.withIssuer(discovered.issuer(), discovered.selectedScopes());
    }
}
