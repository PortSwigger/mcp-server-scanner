package com.mcpscanner.ui;

import com.mcpscanner.auth.*;
import com.mcpscanner.auth.oauth.OAuthAuthorizationFlow;
import com.mcpscanner.auth.oauth.OAuthClientHints;
import com.mcpscanner.auth.oauth.discovery.DiscoveredMetadata;
import com.mcpscanner.auth.oauth.discovery.DiscoveryFailedException;
import com.mcpscanner.auth.oauth.discovery.OAuthMetadataDiscoverer;
import com.mcpscanner.config.ExtensionConfigStore;
import com.mcpscanner.logging.McpEventLog;
import com.mcpscanner.ui.state.ConnectionStatus;
import com.mcpscanner.ui.widgets.HeaderTablePanel;
import com.nimbusds.oauth2.sdk.as.AuthorizationServerMetadata;

import javax.swing.*;
import javax.swing.text.JTextComponent;
import java.awt.BorderLayout;
import java.awt.CardLayout;
import java.awt.Component;
import java.awt.Container;
import java.awt.FlowLayout;
import java.net.URI;
import java.util.List;
import java.util.function.Supplier;

public class ServerConfigPanel extends JPanel implements OAuthConnectSupport {

    public static final String AUTH_NONE = "None";
    public static final String AUTH_BEARER = "Bearer Token";
    public static final String AUTH_CUSTOM = "Custom Headers";
    public static final String AUTH_OAUTH = "OAuth 2.1";
    public static final List<String> AUTH_TYPES = List.of(AUTH_OAUTH, AUTH_BEARER, AUTH_CUSTOM, AUTH_NONE);

    static final String AUTH_NONE_MESSAGE =
            "No configuration required for authentication type \"None\" — "
                    + "select another type (Bearer token, custom header, or OAuth) to configure authentication.";

    private final JTextField tokenField;
    private final HeaderTablePanel headerTablePanel = new HeaderTablePanel();
    private final AuthStrategyFactory authStrategyFactory = new AuthStrategyFactory();
    private final JPanel authCardPanel;

    private final OAuthConfigPanel oauthConfigPanel;

    private String selectedAuthType = AUTH_OAUTH;

    public ServerConfigPanel(ExtensionConfigStore configStore, OAuthAuthorizationFlow authorizationFlow) {
        this(authorizationFlow, OAuthMetadataDiscoverer.defaultInstance());
        oauthConfigPanel.bindConfigStore(configStore);
    }

    public ServerConfigPanel(ExtensionConfigStore configStore,
                             OAuthAuthorizationFlow authorizationFlow,
                             OAuthMetadataDiscoverer discoverer) {
        this(authorizationFlow, discoverer);
        oauthConfigPanel.bindConfigStore(configStore);
    }

    ServerConfigPanel(OAuthAuthorizationFlow authorizationFlow) {
        this(authorizationFlow, OAuthMetadataDiscoverer.defaultInstance());
    }

    ServerConfigPanel(OAuthAuthorizationFlow authorizationFlow, OAuthMetadataDiscoverer discoverer) {
        this(authorizationFlow, new OAuthDiscoveryPresenter(discoverer));
    }

    ServerConfigPanel(OAuthAuthorizationFlow authorizationFlow, OAuthDiscoveryPresenter discoveryPresenter) {
        this(new OAuthConfigPanel(authorizationFlow, discoveryPresenter));
    }

    // Canonical composition ctor — every other ctor chains into this one, injecting the OAuth panel.
    ServerConfigPanel(OAuthConfigPanel oauthConfigPanel) {
        setLayout(new BorderLayout());

        tokenField = new JTextField(30);
        this.oauthConfigPanel = oauthConfigPanel;

        authCardPanel = buildAuthCardPanel();
        add(authCardPanel, BorderLayout.CENTER);
    }

    public AuthStrategy currentAuthStrategy() {
        return buildAuthStrategy(selectedAuthType);
    }

    private AuthStrategy buildAuthStrategy(String authType) {
        return authStrategyFactory.create(
                authType, tokenField.getText(), headerTablePanel.headers(), oauthConfigPanel.currentOauthStrategy());
    }

    public void showAuthCard(String authType) {
        CardLayout layout = (CardLayout) authCardPanel.getLayout();
        layout.show(authCardPanel, authType);
        selectedAuthType = authType;
        oauthConfigPanel.setOauthSelected(AUTH_OAUTH.equals(authType));
    }

    @Override
    public OAuthAuthCodeStrategy completeOAuthDance(OAuthClientHints hints, URI mcpResource, McpEventLog eventLog) {
        return oauthConfigPanel.completeOAuthDance(hints, mcpResource, eventLog);
    }

    @Override
    public OAuthAuthCodeStrategy completeOAuthDance(OAuthClientHints hints, URI mcpResource,
                                                    McpEventLog eventLog,
                                                    AuthorizationServerMetadata preDiscovered) {
        return oauthConfigPanel.completeOAuthDance(hints, mcpResource, eventLog, preDiscovered);
    }

    @Override
    public void publishOauthStrategy(OAuthAuthCodeStrategy strategy) {
        oauthConfigPanel.publishOauthStrategy(strategy);
    }

    @Override
    public OAuthClientHints buildOauthHintsSnapshot() {
        return oauthConfigPanel.buildOauthHintsSnapshot();
    }

    @Override
    public DiscoveredMetadata discoverOauthMetadataSync(String endpoint) throws DiscoveryFailedException {
        return oauthConfigPanel.discoverOauthMetadataSync(endpoint);
    }

    @Override
    public void applyDiscoveredMetadata(DiscoveredMetadata metadata) {
        oauthConfigPanel.applyDiscoveredMetadata(metadata);
    }

    public void setEndpointSupplier(Supplier<String> supplier) {
        oauthConfigPanel.setEndpointSupplier(supplier);
    }

    public void onEndpointChanged() {
        oauthConfigPanel.onEndpointChanged();
    }

    public void setConfigurationLocked(boolean locked) {
        setSubtreeEnabled(authCardPanel, !locked);
        oauthConfigPanel.setConfigurationLocked(locked);
        revalidate();
        repaint();
    }

    private static void setSubtreeEnabled(Component component, boolean enabled) {
        component.setEnabled(enabled);
        if (component instanceof JTextComponent textComponent) {
            textComponent.setEditable(enabled);
        }
        if (component instanceof Container container) {
            for (Component child : container.getComponents()) {
                setSubtreeEnabled(child, enabled);
            }
        }
    }

    @Override
    public ConnectionStatus buildConnectedStatus(String host, int toolCount) {
        return oauthConfigPanel.buildConnectedStatus(host, toolCount);
    }

    public void shutdown() {
        oauthConfigPanel.shutdown();
    }

    @Override
    public void clearOauthStrategy() {
        oauthConfigPanel.clearOauthStrategy();
    }

    @Override
    public void clearAutoDiscoveredOAuth() {
        oauthConfigPanel.clearAutoDiscoveredOAuth();
    }

    JPanel getAuthCardPanel() {
        return authCardPanel;
    }

    JTextField getTokenField() {
        return tokenField;
    }

    HeaderTablePanel getHeaderTablePanel() {
        return headerTablePanel;
    }

    JTextField getOauthIssuerField() {
        return oauthConfigPanel.getOauthIssuerField();
    }

    JButton getDiscoverButton() {
        return oauthConfigPanel.getDiscoverButton();
    }

    @Override
    public OAuthAuthCodeStrategy currentOauthStrategy() {
        return oauthConfigPanel.currentOauthStrategy();
    }

    void setOauthStrategyForTest(OAuthAuthCodeStrategy strategy) {
        oauthConfigPanel.setOauthStrategyForTest(strategy);
    }

    private JPanel buildAuthCardPanel() {
        JPanel cards = new JPanel(new CardLayout());

        JPanel nonePanel = new JPanel(new FlowLayout(FlowLayout.LEFT));
        nonePanel.add(new JLabel(AUTH_NONE_MESSAGE));
        cards.add(nonePanel, AUTH_NONE);

        JPanel bearerPanel = new JPanel(new FlowLayout(FlowLayout.LEFT));
        bearerPanel.add(new JLabel("Token:"));
        bearerPanel.add(tokenField);
        cards.add(bearerPanel, AUTH_BEARER);

        JPanel customPanel = new JPanel(new BorderLayout());
        customPanel.add(headerTablePanel, BorderLayout.CENTER);
        cards.add(customPanel, AUTH_CUSTOM);

        cards.add(oauthConfigPanel, AUTH_OAUTH);
        return cards;
    }

}
