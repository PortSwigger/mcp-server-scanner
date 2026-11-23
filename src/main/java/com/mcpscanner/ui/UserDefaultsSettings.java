package com.mcpscanner.ui;

import com.mcpscanner.config.ExtensionConfigStore;

import javax.swing.JButton;
import javax.swing.JLabel;

final class UserDefaultsSettings {

    static final String LABEL = "Defaults for new projects";
    private static final String SAVED_WITH_SCANNING = "redirect, limit, worker, networking, ping and Send to "
            + "choices, scan mode, checks, request families, header and _meta fuzzing, OAuth redirect port, "
            + "Collect IDs passes and client identity (except its version)";
    private static final String SAVED_WITHOUT_SCANNING = "redirect, limit, networking, ping and Send to choices, "
            + "OAuth redirect port and client identity (except its version)";
    private static final String KEPT_WITH_SCANNING = "The server, users, credentials, OAuth registration, tool "
            + "choices, write-tool opt-ins and the risky Always redirect mode";
    private static final String KEPT_WITHOUT_SCANNING = "The server, users, credentials, OAuth registration and the "
            + "risky Always redirect mode";
    private static final String EXPLANATION = "Save as my defaults: new Burp projects, including temporary ones, "
            + "start with this project's %s. Projects you already have keep their own settings. %s are never saved "
            + "outside the project. Reset my defaults: new projects start from the built-in defaults; this project "
            + "keeps its settings.";
    static final String SAVE = "Save as my defaults";
    static final String RESET = "Reset my defaults";
    static final String SAVED = "Saved. New projects start with these settings.";
    static final String CLEARED = "Your defaults are cleared. New projects start from the built-in defaults.";

    private final ExtensionConfigStore configStore;
    private final SettingsScope scope;
    private final JButton saveButton = new JButton(SAVE);
    private final JButton resetButton = new JButton(RESET);
    private final JLabel status = new JLabel(" ");

    UserDefaultsSettings(ExtensionConfigStore configStore, SettingsScope scope) {
        this.configStore = configStore;
        this.scope = scope;
        saveButton.addActionListener(event -> save());
        resetButton.addActionListener(event -> reset());
    }

    String explanation() {
        return scope.includesScanning()
                ? EXPLANATION.formatted(SAVED_WITH_SCANNING, KEPT_WITH_SCANNING)
                : EXPLANATION.formatted(SAVED_WITHOUT_SCANNING, KEPT_WITHOUT_SCANNING);
    }

    JButton saveButton() {
        return saveButton;
    }

    JButton resetButton() {
        return resetButton;
    }

    JLabel status() {
        return status;
    }

    private void save() {
        configStore.saveAsUserDefaults();
        status.setText(SAVED);
    }

    private void reset() {
        configStore.resetUserDefaults();
        status.setText(CLEARED);
    }
}
