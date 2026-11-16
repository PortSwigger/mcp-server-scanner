package com.mcpscanner.ui;

import com.mcpscanner.auth.grants.ClientAuthenticationProviderRegistry;
import com.mcpscanner.auth.grants.EnterpriseIdentityProviderRegistry;
import com.mcpscanner.auth.oauth.discovery.OAuthMetadataDiscoverer;
import com.mcpscanner.config.ExtensionConfigStore;
import com.mcpscanner.testutil.TestOAuthFlows;

import java.util.List;

import static org.mockito.Mockito.CALLS_REAL_METHODS;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.withSettings;

final class ServerConfigPanels {

    private ServerConfigPanels() {
    }

    static ServerConfigPanel unbound() {
        return around(new OAuthConfigPanel(TestOAuthFlows.recording(),
                new OAuthDiscoveryPresenter(mock(OAuthMetadataDiscoverer.class)),
                TestDialogOwners.withoutSuiteFrame()));
    }

    static ServerConfigPanel boundTo(ExtensionConfigStore configStore) {
        return ServerConfigPanel.create(configStore, TestOAuthFlows.recording(), null, () -> { },
                TestDialogOwners.withoutSuiteFrame());
    }

    static ServerConfigPanel around(OAuthConfigPanel oauth) {
        return new ServerConfigPanel(oauth, new ClientAuthenticationProviderRegistry(List.of()),
                EnterpriseIdentityProviderRegistry.loadOrEmpty());
    }

    static OAuthConfigPanel spiedOAuthPanel(ExtensionConfigStore configStore) {
        OAuthConfigPanel spy = mock(OAuthConfigPanel.class, withSettings()
                .useConstructor(TestOAuthFlows.recording(),
                        new OAuthDiscoveryPresenter(OAuthMetadataDiscoverer.defaultInstance()),
                        TestDialogOwners.withoutSuiteFrame())
                .defaultAnswer(CALLS_REAL_METHODS));
        spy.bindConfigStore(configStore);
        return spy;
    }
}
