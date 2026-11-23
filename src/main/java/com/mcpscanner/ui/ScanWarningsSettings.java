package com.mcpscanner.ui;

import com.mcpscanner.config.ExtensionConfigStore;
import com.mcpscanner.ui.widgets.Plurals;

import javax.swing.JButton;
import javax.swing.JLabel;

final class ScanWarningsSettings {

    static final String LABEL = "Scan warnings";
    static final String EXPLANATION =
            "Before scanning tools the server doesn't mark as read-only, the extension asks you to confirm, because "
                    + "scanning can change or delete data. Ticking \"Don't ask me again for this server\" skips "
                    + "that question for that server. Reset to ask again on every server.";
    static final String RESET = "Reset “Don't ask again”";

    private final ExtensionConfigStore configStore;
    private final JButton resetButton = new JButton(RESET);
    private final JLabel status = new JLabel(" ");

    ScanWarningsSettings(ExtensionConfigStore configStore) {
        this.configStore = configStore;
        resetButton.addActionListener(event -> reset());
    }

    JButton resetButton() {
        return resetButton;
    }

    JLabel status() {
        return status;
    }

    private void reset() {
        int cleared = configStore.clearDontAskAgainForAllServers();
        status.setText(cleared == 0
                ? "No server had “Don't ask again” set."
                : "Scan warnings turned back on for " + Plurals.count(cleared, "server") + ".");
    }
}
