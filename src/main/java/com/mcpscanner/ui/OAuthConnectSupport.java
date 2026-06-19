package com.mcpscanner.ui;

import com.mcpscanner.auth.OAuthAuthCodeStrategy;
import com.mcpscanner.auth.oauth.OAuthClientHints;
import com.mcpscanner.auth.oauth.discovery.DiscoveredMetadata;
import com.mcpscanner.auth.oauth.discovery.DiscoveryFailedException;
import com.mcpscanner.logging.McpEventLog;
import com.mcpscanner.ui.state.ConnectionStatus;

import java.net.URI;

/**
 * Narrow contract for the OAuth operations the connect flow drives. Implemented by
 * {@link OAuthConfigPanel} and delegated to by {@link ServerConfigPanel}, so the connect
 * coordinator (and the tab) can complete an OAuth dance without reaching into Swing internals.
 */
public interface OAuthConnectSupport {

    OAuthClientHints buildOauthHintsSnapshot();

    DiscoveredMetadata discoverOauthMetadataSync(String endpoint) throws DiscoveryFailedException;

    void applyDiscoveredMetadata(DiscoveredMetadata metadata);

    OAuthAuthCodeStrategy completeOAuthDance(OAuthClientHints hints, URI mcpResource, McpEventLog eventLog);

    void publishOauthStrategy(OAuthAuthCodeStrategy strategy);

    void clearOauthStrategy();

    void clearAutoDiscoveredOAuth();

    OAuthAuthCodeStrategy currentOauthStrategy();

    ConnectionStatus buildConnectedStatus(String host, int toolCount);
}
