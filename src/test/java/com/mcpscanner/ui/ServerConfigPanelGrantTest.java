package com.mcpscanner.ui;

import com.mcpscanner.auth.grants.ClientAuthenticationProviderRegistry;
import com.mcpscanner.auth.grants.EnterpriseIdentityProviderRegistry;
import com.mcpscanner.auth.grants.OptionalGrantSettings;
import com.mcpscanner.auth.oauth.discovery.OAuthMetadataDiscoverer;
import com.mcpscanner.identity.IdentityAuthKind;
import com.mcpscanner.testutil.SwingTree;
import com.mcpscanner.testutil.TestOAuthFlows;
import com.mcpscanner.ui.widgets.LabeledForm;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicInteger;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;

class ServerConfigPanelGrantTest {

    @Test
    void theOAuthClientHasNoGrantChoice() {
        assertThat(SwingTree.labelledField(panelWith(Map.of()), "Grant:")).isEmpty();
    }

    @Test
    void enterpriseManagedIsOfferedOnlyOnceAnIdentityProviderIsInstalled() {
        assertThat(panelWith(Map.of()).grantForms().offers(IdentityAuthKind.OAUTH_ENTERPRISE_MANAGED)).isFalse();
        assertThat(panelWith(Map.of("company", request -> null)).grantForms()
                .offers(IdentityAuthKind.OAUTH_ENTERPRISE_MANAGED)).isTrue();
        assertThat(panelWith(Map.of()).grantForms().offers(IdentityAuthKind.OAUTH_CLIENT_CREDENTIALS)).isTrue();
    }

    @Test
    void onlyTheShownKindsFieldsAreVisible() {
        var forms = panelWith(Map.of("company", request -> null)).grantForms();
        LabeledForm form = new LabeledForm();
        forms.addTo(form);

        forms.show(IdentityAuthKind.OAUTH_CLIENT_CREDENTIALS);

        assertThat(forms.fieldsFor(OptionalGrantSettings.Profile.CLIENT_CREDENTIALS).clientIdField().isVisible())
                .isTrue();
        assertThat(forms.fieldsFor(OptionalGrantSettings.Profile.ENTERPRISE_MANAGED).clientIdField().isVisible())
                .isFalse();

        forms.show(IdentityAuthKind.BEARER);

        assertThat(forms.fieldsFor(OptionalGrantSettings.Profile.CLIENT_CREDENTIALS).clientIdField().isVisible())
                .isFalse();
    }

    @Test
    void aGrantIsBlockedByItsOwnSettings() {
        var panel = panelWith(Map.of());

        assertThat(panel.grantForms().blocker(OptionalGrantSettings.Profile.CLIENT_CREDENTIALS))
                .hasValueSatisfying(reason -> assertThat(reason).contains("client ID"));
    }

    @Test
    void readinessListenerFiresWhenAGrantFieldChanges() {
        var panel = panelWith(Map.of());
        var notifications = new AtomicInteger();
        panel.setReadinessListener(notifications::incrementAndGet);
        panel.grantForms().addTo(new LabeledForm());

        panel.grantForms().fieldsFor(OptionalGrantSettings.Profile.CLIENT_CREDENTIALS).clientIdField().setText("c");

        assertThat(notifications.get()).isPositive();
    }

    private static ServerConfigPanel panelWith(Map<String, com.mcpscanner.core.oauth.EnterpriseIdentityProvider> providers) {
        var oauth = new OAuthConfigPanel(TestOAuthFlows.recording(),
                new OAuthDiscoveryPresenter(mock(OAuthMetadataDiscoverer.class)),
                TestDialogOwners.withoutSuiteFrame());
        return new ServerConfigPanel(oauth, new ClientAuthenticationProviderRegistry(List.of()),
                new EnterpriseIdentityProviderRegistry(providers));
    }
}
