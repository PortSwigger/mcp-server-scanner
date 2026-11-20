package com.mcpscanner.config;

import burp.api.montoya.logging.Logging;
import burp.api.montoya.persistence.PersistedObject;
import com.mcpscanner.testutil.InMemoryPersistedObject;
import com.mcpscanner.testutil.InMemoryPreferences;
import org.junit.jupiter.api.Test;

import java.util.ArrayList;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;

class SignedInConsentSettingTest {

    private final PersistedObject project = InMemoryPersistedObject.create();
    private final SignedInConsentSetting setting =
            new SignedInConsentSetting(new ExtensionConfigStore(project, new InMemoryPreferences(), mock(Logging.class)));

    @Test
    void isOffByDefault() {
        assertThat(setting.optedIn()).isFalse();
    }

    @Test
    void optingInIsSavedInTheProject() {
        setting.optIn(true);

        assertThat(project.getBoolean(SettingKey.OAUTH_CONSENT_SIGNED_IN.key())).isTrue();
        assertThat(new SignedInConsentSetting(new ExtensionConfigStore(project, new InMemoryPreferences(), mock(Logging.class))).optedIn())
                .isTrue();
    }

    @Test
    void isAProjectOnlySettingUnderTheConsentKey() {
        assertThat(SettingKey.OAUTH_CONSENT_SIGNED_IN.key()).isEqualTo("mcp.oauth.consent.signed_in");
        assertThat(SettingKey.OAUTH_CONSENT_SIGNED_IN.scope()).isEqualTo(SettingScope.PROJECT_ONLY);
    }

    @Test
    void tellsListenersWhenTheChoiceChanges() {
        List<Boolean> seen = new ArrayList<>();
        setting.addListener(seen::add);

        setting.optIn(true);
        setting.optIn(false);

        assertThat(seen).containsExactly(true, false);
    }
}
