package com.mcpscanner.ui.connect;

import com.mcpscanner.auth.AuthStrategy;
import com.mcpscanner.auth.OAuthAuthCodeStrategy;
import com.mcpscanner.auth.oauth.OAuthClientHints;
import com.mcpscanner.auth.oauth.discovery.DiscoveredMetadata;
import com.mcpscanner.client.ConnectResult;
import com.nimbusds.oauth2.sdk.as.AuthorizationServerMetadata;
import com.mcpscanner.client.McpClientManager;
import com.mcpscanner.client.McpServerConfig;
import com.mcpscanner.logging.McpEventLog;
import com.mcpscanner.ui.OAuthConnectSupport;
import com.mcpscanner.ui.ServerConfigPanel;
import com.mcpscanner.ui.state.ConnectAttempt;
import com.mcpscanner.ui.state.ConnectPhase;

import java.util.Objects;

/**
 * Swing-free orchestration of a single connect attempt. Runs entirely off the EDT inside the tab's
 * SwingWorker. Depends only on the narrow {@link OAuthConnectSupport} contract (not the concrete
 * Swing panel), {@link McpClientManager}, and the {@link McpEventLog}, so it is unit-testable with
 * plain mocks.
 *
 * <p>Preserves the exact original orchestration: resolve auth, auto-discover OAuth metadata when the
 * issuer is null (merging the discovered issuer into the hints), complete the OAuth dance, wire the
 * terminal-failure callback onto the resulting strategy, build the server config, and connect.
 */
public final class ConnectCoordinator {

    private final OAuthConnectSupport support;
    private final McpClientManager clientManager;
    private final McpEventLog eventLog;

    public ConnectCoordinator(OAuthConnectSupport support, McpClientManager clientManager, McpEventLog eventLog) {
        this.support = Objects.requireNonNull(support, "support must not be null");
        this.clientManager = Objects.requireNonNull(clientManager, "clientManager must not be null");
        this.eventLog = Objects.requireNonNull(eventLog, "eventLog must not be null");
    }

    public ConnectionAttemptResult connect(ConnectAttempt attempt,
                                           ProgressReporter progress,
                                           Runnable terminalFailureCallback) {
        AuthStrategy resolved = attempt.snapshotAuth();
        OAuthAuthCodeStrategy oauthStrategy = null;
        if (ServerConfigPanel.AUTH_OAUTH.equals(attempt.authType())) {
            OAuthClientHints hintsForDance = attempt.oauthHints();
            DiscoveredMetadata discovered = null;
            if (hintsForDance != null && hintsForDance.issuer() == null) {
                progress.report(ConnectPhase.DISCOVER, "Discovering OAuth metadata…");
                discovered = support.discoverOauthMetadataSync(attempt.endpoint());
                support.applyDiscoveredMetadata(discovered);
                hintsForDance = withDiscovered(hintsForDance, discovered);
            }
            progress.report(ConnectPhase.OAUTH, "OAuth: opening browser…");
            AuthorizationServerMetadata preDiscovered = discovered != null ? discovered.asMetadata() : null;
            oauthStrategy = support.completeOAuthDance(hintsForDance, attempt.mcpResource(), eventLog, preDiscovered);
            oauthStrategy.setTerminalFailureListener(terminalFailureCallback);
            resolved = oauthStrategy;
            progress.report(ConnectPhase.CONNECT, "Listing tools…");
        }
        McpServerConfig cfg = new McpServerConfig(attempt.endpoint(), attempt.transport(), resolved);
        ConnectResult result = clientManager.connect(cfg);
        return new ConnectionAttemptResult(result, oauthStrategy);
    }

    private static OAuthClientHints withDiscovered(OAuthClientHints base, DiscoveredMetadata discovered) {
        Objects.requireNonNull(discovered.issuer(), "discovered issuer must not be null");
        return new OAuthClientHints(
                discovered.issuer(),
                discovered.advertisedScopes(),
                base.clientId(),
                base.clientSecret(),
                base.allowDcr(),
                base.redirectPort(),
                base.timeout());
    }
}
