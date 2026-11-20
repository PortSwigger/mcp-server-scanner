package com.mcpscanner.ui;

import com.mcpscanner.config.SignedInConsentSetting;
import com.mcpscanner.testutil.InMemoryPersistedObject;
import com.mcpscanner.testutil.SwingTree;
import org.junit.jupiter.api.Test;

import javax.swing.JCheckBox;
import javax.swing.text.JTextComponent;

import static org.assertj.core.api.Assertions.assertThat;

class SignedInConsentOptionTest {

    private final SignedInConsentSetting setting = new SignedInConsentSetting(InMemoryPersistedObject.configStore());

    @Test
    void isUntickedByDefault() {
        assertThat(box(new SignedInConsentOption(setting)).isSelected()).isFalse();
    }

    @Test
    void tickingItOptsTheProjectIn() {
        box(new SignedInConsentOption(setting)).doClick();

        assertThat(setting.optedIn()).isTrue();
    }

    @Test
    void showsTheSavedChoice() {
        setting.optIn(true);

        assertThat(box(new SignedInConsentOption(setting)).isSelected()).isTrue();
    }

    @Test
    void explainsWhatTheTestDoesWithTheUsersAccount() {
        String hint = hint(new SignedInConsentOption(setting));

        assertThat(hint).contains("Burp's cookies for the authorization server")
                .contains("your browser right after an OAuth sign-in at Connect")
                .contains("obtains a token in your name and then revokes it")
                .contains("registers and deletes probe OAuth clients")
                .contains("close it, do not approve it");
    }

    private static JCheckBox box(SignedInConsentOption option) {
        return SwingTree.descendants(option).stream().filter(JCheckBox.class::isInstance).map(JCheckBox.class::cast)
                .filter(box -> box.getText().equals(SignedInConsentOption.LABEL)).findFirst().orElseThrow();
    }

    private static String hint(SignedInConsentOption option) {
        return SwingTree.descendants(option).stream().filter(JTextComponent.class::isInstance)
                .map(component -> ((JTextComponent) component).getText()).reduce("", String::concat);
    }
}
