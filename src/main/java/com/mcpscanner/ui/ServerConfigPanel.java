package com.mcpscanner.ui;

import com.mcpscanner.ui.widgets.DialogOwner;
import com.mcpscanner.auth.grants.ClientAuthenticationProviderRegistry;
import com.mcpscanner.auth.grants.EnterpriseIdentityProviderRegistry;
import com.mcpscanner.auth.oauth.OAuthAuthorizationFlow;
import com.mcpscanner.auth.oauth.discovery.OAuthMetadataDiscoverer;
import com.mcpscanner.config.ExtensionConfigStore;

import javax.swing.JPanel;
import java.awt.BorderLayout;
import java.util.Objects;

public class ServerConfigPanel extends JPanel {

    private final OAuthConfigPanel oauthConfigPanel;
    private final OptionalGrantForms grantForms;
    private Runnable readinessListener = () -> { };

    ServerConfigPanel(OAuthConfigPanel oauthConfigPanel, ClientAuthenticationProviderRegistry signers,
                      EnterpriseIdentityProviderRegistry identityProviders) {
        super(new BorderLayout());
        this.oauthConfigPanel = oauthConfigPanel;
        this.grantForms = new OptionalGrantForms(signers, identityProviders);
        oauthConfigPanel.setChangeListener(this::notifyReadinessChanged);
        grantForms.setChangeListener(this::notifyReadinessChanged);
        add(oauthConfigPanel, BorderLayout.CENTER);
    }

    public static ServerConfigPanel create(ExtensionConfigStore configStore, OAuthAuthorizationFlow authorizationFlow,
                                           OAuthMetadataDiscoverer discoverer, Runnable signInAttemptStart,
                                           DialogOwner dialogOwner) {
        OAuthMetadataDiscoverer effectiveDiscoverer =
                Objects.requireNonNullElseGet(discoverer, OAuthMetadataDiscoverer::defaultInstance);
        OAuthConfigPanel oauth = new OAuthConfigPanel(authorizationFlow, new OAuthDiscoveryPresenter(effectiveDiscoverer),
                signInAttemptStart, dialogOwner);
        oauth.bindConfigStore(configStore);
        return new ServerConfigPanel(oauth, ClientAuthenticationProviderRegistry.load(),
                EnterpriseIdentityProviderRegistry.loadOrEmpty());
    }

    public OAuthConfigPanel oauthConfig() {
        return oauthConfigPanel;
    }

    OptionalGrantForms grantForms() {
        return grantForms;
    }

    public void setReadinessListener(Runnable listener) {
        this.readinessListener = listener;
    }

    public void clearGrantSecrets() {
        grantForms.clearSecrets();
    }

    public void clearEstablishedAuth() {
        clearGrantSecrets();
        oauthConfigPanel.clearOauthStrategy();
    }

    public void setConfigurationLocked(boolean locked) {
        oauthConfigPanel.setConfigurationLocked(locked);
        revalidate();
        repaint();
    }

    public void shutdown() {
        clearGrantSecrets();
        oauthConfigPanel.shutdown();
    }

    private void notifyReadinessChanged() {
        readinessListener.run();
    }
}
