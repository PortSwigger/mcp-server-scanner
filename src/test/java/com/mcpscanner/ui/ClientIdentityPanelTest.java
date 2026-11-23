package com.mcpscanner.ui;

import com.mcpscanner.testutil.InMemoryPreferences;
import burp.api.montoya.logging.Logging;
import burp.api.montoya.persistence.PersistedObject;
import com.mcpscanner.config.ClientIdentity;
import com.mcpscanner.config.ClientIdentityField;
import com.mcpscanner.config.ExtensionConfigStore;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;

class ClientIdentityPanelTest {

    private PersistedObject persisted;
    private ClientIdentityPanel panel;

    @BeforeEach
    void setUp() {
        persisted = mock(PersistedObject.class);
        panel = new ClientIdentityPanel(new ExtensionConfigStore(persisted, new InMemoryPreferences(), mock(Logging.class)));
    }

    @Test
    void showsDefaultsWhenNothingIsStored() {
        assertThat(panel.input(ClientIdentityField.NAME).getText())
                .isEqualTo(ClientIdentity.defaults().value(ClientIdentityField.NAME));
        assertThat(panel.input(ClientIdentityField.TITLE).getText()).isEmpty();
    }

    @Test
    void applyPersistsEditedValues() {
        panel.input(ClientIdentityField.TITLE).setText("Acme");

        panel.apply();

        verify(persisted).setString("mcp.client.title", "Acme");
        assertThat(panel.statusText()).contains("next handshake or registration");
    }

    @Test
    void invalidUrlIsReportedAndNotPersisted() {
        panel.input(ClientIdentityField.WEBSITE_URL).setText("javascript:alert(1)");

        panel.apply();

        assertThat(panel.statusText()).contains("Website URL");
        verify(persisted, never()).setString("mcp.client.website_url", "javascript:alert(1)");
    }

    @Test
    void resetRestoresDefaultsInFieldsAndStore() {
        panel.input(ClientIdentityField.TITLE).setText("Acme");

        panel.reset();

        assertThat(panel.input(ClientIdentityField.TITLE).getText()).isEmpty();
        verify(persisted).setString("mcp.client.title", "");
    }

    @Test
    void inATallViewportTheFormIsTopAlignedWithApplyRightBelowIt() {
        panel.setSize(600, 1600);
        layOut(panel);

        java.awt.Component heading = find(ClientIdentityPanel.HANDSHAKE_HEADING);
        java.awt.Component apply = find(ClientIdentityPanel.APPLY_LABEL);
        int headingTop = javax.swing.SwingUtilities.convertPoint(heading.getParent(), heading.getLocation(), panel).y;
        int applyTop = javax.swing.SwingUtilities.convertPoint(apply.getParent(), apply.getLocation(), panel).y;

        assertThat(headingTop).isLessThan(40);
        assertThat(applyTop).isLessThan(panel.getPreferredSize().height);
    }

    private java.awt.Component find(String text) {
        return com.mcpscanner.testutil.SwingTree.descendants(panel).stream()
                .filter(c -> (c instanceof javax.swing.JLabel l && text.equals(l.getText()))
                        || (c instanceof javax.swing.AbstractButton b && text.equals(b.getText())))
                .findFirst().orElseThrow();
    }

    private static void layOut(java.awt.Container container) {
        container.doLayout();
        for (java.awt.Component child : container.getComponents()) {
            if (child instanceof java.awt.Container nested) {
                layOut(nested);
            }
        }
    }
}
