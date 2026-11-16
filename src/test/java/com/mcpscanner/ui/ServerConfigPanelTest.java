package com.mcpscanner.ui;

import com.mcpscanner.auth.oauth.discovery.OAuthMetadataDiscoverer;
import com.mcpscanner.testutil.SwingTree;
import com.mcpscanner.testutil.TestOAuthFlows;
import com.mcpscanner.ui.widgets.HeaderTablePanel;
import com.mcpscanner.ui.widgets.WrappingText;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.spy;
import static org.mockito.Mockito.verify;

class ServerConfigPanelTest {

    private final ServerConfigPanel panel = ServerConfigPanels.unbound();

    @Test
    void holdsOnlyTheSharedOAuthClientAndNoCredentialFields() {
        assertThat(SwingTree.labelledField(panel, "Issuer URL:")).isPresent();
        assertThat(SwingTree.labelledField(panel, "Grant:")).isEmpty();
        assertThat(SwingTree.labelledField(panel, "Token:")).isEmpty();
        assertThat(SwingTree.descendants(panel)).noneMatch(HeaderTablePanel.class::isInstance);
    }

    @Test
    void exposesTheInjectedOauthPanel() {
        OAuthConfigPanel oauth = spyOauthPanel();

        assertThat(ServerConfigPanels.around(oauth).oauthConfig()).isSameAs(oauth);
    }

    @Test
    void configurationLockReachesTheOauthPanel() {
        OAuthConfigPanel spyOauth = spyOauthPanel();
        ServerConfigPanel host = ServerConfigPanels.around(spyOauth);

        host.setConfigurationLocked(true);

        verify(spyOauth).setConfigurationLocked(true);
    }

    @Test
    void clearingEstablishedAuthClearsTheOauthStrategy() {
        OAuthConfigPanel spyOauth = spyOauthPanel();
        ServerConfigPanel host = ServerConfigPanels.around(spyOauth);

        host.clearEstablishedAuth();

        verify(spyOauth).clearOauthStrategy();
    }

    private static OAuthConfigPanel spyOauthPanel() {
        return spy(new OAuthConfigPanel(
                TestOAuthFlows.recording(),
                new OAuthDiscoveryPresenter(mock(OAuthMetadataDiscoverer.class)),
                TestDialogOwners.withoutSuiteFrame()));
    }
}
