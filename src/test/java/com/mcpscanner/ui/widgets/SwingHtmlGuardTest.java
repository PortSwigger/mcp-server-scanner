package com.mcpscanner.ui.widgets;

import org.junit.jupiter.api.Test;

import javax.swing.JLabel;

import static org.assertj.core.api.Assertions.assertThat;

class SwingHtmlGuardTest {

    @Test
    void disableHtmlSetsClientProperty() {
        JLabel label = new JLabel();

        SwingHtmlGuard.disableHtml(label);

        assertThat(label.getClientProperty("html.disable")).isEqualTo(Boolean.TRUE);
    }

    @Test
    void disableHtmlReturnsSameComponent() {
        JLabel label = new JLabel();

        assertThat(SwingHtmlGuard.disableHtml(label)).isSameAs(label);
    }
}
