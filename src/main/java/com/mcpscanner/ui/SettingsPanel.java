package com.mcpscanner.ui;

import com.mcpscanner.ExtensionMetadata;
import com.mcpscanner.client.BurpNetworkingSetting;
import com.mcpscanner.config.RedirectMode;
import com.mcpscanner.config.ExtensionConfigStore;
import com.mcpscanner.config.CapKind;
import com.mcpscanner.config.ResourceCap;
import com.mcpscanner.mcp.ScannerSentinels;
import com.mcpscanner.ui.widgets.Plurals;
import com.mcpscanner.ui.widgets.WrapLayout;
import com.mcpscanner.ui.widgets.WrappingText;

import javax.swing.BorderFactory;
import javax.swing.Box;
import javax.swing.BoxLayout;
import javax.swing.JButton;
import javax.swing.JCheckBox;
import javax.swing.JComboBox;
import javax.swing.JComponent;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JTextField;
import javax.swing.SwingUtilities;
import java.awt.BorderLayout;
import java.awt.FlowLayout;
import java.util.Arrays;
import java.util.EnumMap;
import java.util.Map;
import java.util.Set;

public final class SettingsPanel extends JPanel {
    private static final String SEND_TO_AUTHENTICATION_LABEL =
            "Handle auth and sessions in Burp tools";
    private static final String SEND_TO_AUTHENTICATION_EXPLANATION =
            "On: requests you send to Repeater, Intruder and other Burp tools still go through the extension. It "
                    + "adds the current credentials, renewing an expired OAuth token, and the live MCP session, "
                    + "starting a new one if the server dropped it. It marks these requests with a "
                    + ScannerSentinels.AUDIT_CAPABILITY_HEADER + " header and removes it before they reach the "
                    + "server. Off: requests go straight to the server with the credentials and session as they "
                    + "were when you sent them, so an expired token or session stays expired.";
    private static final String SERVER_PINGS_LABEL = "Answer server pings";
    private static final String SERVER_PINGS_EXPLANATION =
            "On: when a server sends a JSON-RPC ping while a reply is streaming, the extension answers it with the "
                    + "session's headers so the server goes on to send the reply.";
    private static final String BURP_NETWORKING_EXPLANATION =
            "On: the extension's HTTP requests to the MCP server go through Burp, so Burp's client TLS certificates, "
                    + "upstream proxy and TLS settings apply. Turn it off if a server streams its replies (Burp "
                    + "doesn't pass streamed replies to extensions) or waits for a ping answer before replying. "
                    + "Off: requests go directly from the extension and ignore those Burp settings. SSE connections "
                    + "always go directly. Changes apply from the next request.";
    private static final Set<String> KEYWORDS = Set.of("MCP", "Redirect", "Proxy", "POST body", "Repeater",
            "Send to", "Authentication", "Limits", "Discovery", "SSE", "Traversal", "Ping", "TLS", "Network",
            "Streaming", "Workers", "Concurrency", "Extension scan", "Collect IDs");
    private static final String RESOURCE_LIMITS_EXPLANATION =
            "Safety limits against hostile servers. Raise one if the Logger reports it truncated a scan or "
                    + "discovery. Leave blank to restore the default. Collect IDs requests per user is 0 by "
                    + "default: Collect IDs sends whatever its passes need; set a number to stop each user sooner.";
    private static final String EXTENSION_SCAN_WORKERS_EXPLANATION =
            "How many checks extension scans run at once; each sends its requests one after another. Raise it to "
                    + "scan faster, lower it to go easier on the server. Running scans share these workers: a change "
                    + "takes effect when the next scan starts, and then applies to every scan still running. Nothing "
                    + "in progress is interrupted. Leave blank to restore the default.";
    private static final String SCAN_WARNINGS_LABEL = "Scan warnings";
    private static final String SCAN_WARNINGS_EXPLANATION =
            "Before scanning tools the server doesn't mark as read-only, the extension asks you to confirm, because "
                    + "scanning can change or delete data. Ticking \"Don't ask me again for this server\" skips "
                    + "that question for that server. Reset to ask again on every server.";
    static final String RESET_SCAN_WARNINGS = "Reset \u201cDon't ask again\u201d";
    private static final String BURP_SETTINGS_HINT =
            "Also in Burp: Settings > Extensions > " + ExtensionMetadata.NAME;

    private final ExtensionConfigStore configStore;
    private final JComboBox<RedirectMode> redirectModeSelector = new JComboBox<>(RedirectMode.values());
    private final WrappingText redirectExplanation = explanation(RedirectMode.METHOD_PRESERVING_SAME_ORIGIN.description());
    private final Map<ResourceCap, ResourceCapField> capFields = new EnumMap<>(ResourceCap.class);
    private final JCheckBox sendToAuthenticationCheckbox = new JCheckBox(SEND_TO_AUTHENTICATION_LABEL);
    private final JCheckBox serverPingsCheckbox = new JCheckBox(SERVER_PINGS_LABEL);
    private final JCheckBox burpNetworkingCheckbox = new JCheckBox(BurpNetworkingSetting.NAME);
    private final JButton resetScanWarningsButton = new JButton(RESET_SCAN_WARNINGS);
    private final JLabel scanWarningsStatus = new JLabel(" ");
    private final JButton burpSettingsButton = new JButton("Open Burp Settings");
    private final JPanel burpSettingsRow = burpSettingsRow();
    private boolean updatingFromConfig;
    private boolean savingToConfig;

    public SettingsPanel(ExtensionConfigStore configStore) {
        super(new BorderLayout());
        this.configStore = configStore;
        Arrays.stream(ResourceCap.values())
                .forEach(cap -> capFields.put(cap, new ResourceCapField(cap, configStore, this::whileSaving)));

        JPanel settings = new JPanel();
        settings.setLayout(new BoxLayout(settings, BoxLayout.Y_AXIS));
        settings.setBorder(BorderFactory.createEmptyBorder(12, 12, 12, 12));
        settings.add(redirectRow());
        settings.add(redirectExplanation);
        settings.add(Box.createVerticalStrut(16));
        settings.add(explanation(RESOURCE_LIMITS_EXPLANATION));
        addCapRows(settings, CapKind.SAFETY_LIMIT);
        settings.add(Box.createVerticalStrut(16));
        addCapRows(settings, CapKind.SCAN_THROUGHPUT);
        settings.add(explanation(EXTENSION_SCAN_WORKERS_EXPLANATION));
        settings.add(Box.createVerticalStrut(16));
        settings.add(checkboxRow(sendToAuthenticationCheckbox));
        settings.add(explanation(SEND_TO_AUTHENTICATION_EXPLANATION));
        settings.add(Box.createVerticalStrut(16));
        settings.add(checkboxRow(serverPingsCheckbox));
        settings.add(explanation(SERVER_PINGS_EXPLANATION));
        settings.add(Box.createVerticalStrut(16));
        settings.add(checkboxRow(burpNetworkingCheckbox));
        settings.add(explanation(BURP_NETWORKING_EXPLANATION));
        settings.add(Box.createVerticalStrut(16));
        addScanWarnings(settings);
        settings.add(Box.createVerticalStrut(16));
        settings.add(burpSettingsRow);
        add(settings, BorderLayout.NORTH);

        refreshFromConfig();
        redirectModeSelector.addActionListener(event -> {
            explainSelectedRedirectMode();
            if (!updatingFromConfig) {
                whileSaving(() -> configStore.setRedirectMode((RedirectMode) redirectModeSelector.getSelectedItem()));
            }
        });
        sendToAuthenticationCheckbox.addActionListener(event -> saveSendToAuthentication());
        serverPingsCheckbox.addActionListener(event -> saveServerPings());
        burpNetworkingCheckbox.addActionListener(event -> saveBurpNetworking());
        resetScanWarningsButton.addActionListener(event -> resetScanWarnings());
        configStore.addSettingsChangeListener(() -> {
            if (!savingToConfig) {
                if (SwingUtilities.isEventDispatchThread()) {
                    refreshFromConfig();
                } else {
                    SwingUtilities.invokeLater(this::refreshFromConfig);
                }
            }
        });
    }

    public burp.api.montoya.ui.settings.SettingsPanel asBurpSettingsPanel() {
        return new burp.api.montoya.ui.settings.SettingsPanel() {
            @Override
            public javax.swing.JComponent uiComponent() {
                return SettingsPanel.this;
            }

            @Override
            public Set<String> keywords() {
                return KEYWORDS;
            }
        };
    }

    public void offerBurpSettings(Runnable openBurpSettings) {
        burpSettingsButton.addActionListener(event -> openBurpSettings.run());
        burpSettingsRow.setVisible(true);
    }

    private JPanel burpSettingsRow() {
        JPanel row = new JPanel(new BorderLayout(0, 4));
        row.add(explanation(BURP_SETTINGS_HINT), BorderLayout.NORTH);
        JPanel buttonRow = optionRow();
        buttonRow.add(burpSettingsButton);
        row.add(buttonRow, BorderLayout.CENTER);
        row.setAlignmentX(LEFT_ALIGNMENT);
        row.setVisible(false);
        return row;
    }

    private static WrappingText explanation(String text) {
        WrappingText explanation = new WrappingText(text).muted();
        explanation.setAlignmentX(LEFT_ALIGNMENT);
        return explanation;
    }

    private static JPanel optionRow() {
        JPanel row = new JPanel(new WrapLayout(FlowLayout.LEADING, 0, 4));
        row.setAlignmentX(LEFT_ALIGNMENT);
        return row;
    }

    private JPanel redirectRow() {
        return labelAbove("Follow MCP redirects", redirectModeSelector);
    }

    private void addCapRows(JPanel settings, CapKind kind) {
        ResourceCap.ofKind(kind).forEach(cap -> addCapRow(settings, capFields.get(cap)));
    }

    private static void addCapRow(JPanel settings, ResourceCapField capField) {
        settings.add(Box.createVerticalStrut(8));
        settings.add(labelAbove(capField.cap().label(), capField.field()));
        capField.status().setAlignmentX(LEFT_ALIGNMENT);
        settings.add(capField.status());
    }

    private static JPanel labelAbove(String label, JComponent input) {
        JPanel row = new JPanel(new BorderLayout(0, 4));
        row.add(new JLabel(label), BorderLayout.NORTH);
        JPanel inputRow = new JPanel(new FlowLayout(FlowLayout.LEADING, 0, 0));
        inputRow.add(input);
        row.add(inputRow, BorderLayout.CENTER);
        row.setAlignmentX(LEFT_ALIGNMENT);
        return row;
    }

    private void addScanWarnings(JPanel settings) {
        settings.add(labelAbove(SCAN_WARNINGS_LABEL, resetScanWarningsButton));
        settings.add(explanation(SCAN_WARNINGS_EXPLANATION));
        scanWarningsStatus.setAlignmentX(LEFT_ALIGNMENT);
        settings.add(scanWarningsStatus);
    }

    private void explainSelectedRedirectMode() {
        redirectExplanation.setText(((RedirectMode) redirectModeSelector.getSelectedItem()).description());
    }

    private void resetScanWarnings() {
        int cleared = configStore.clearDontAskAgainForAllServers();
        scanWarningsStatus.setText(cleared == 0
                ? "No server had \u201cDon't ask again\u201d set."
                : "Scan warnings turned back on for " + Plurals.count(cleared, "server") + ".");
    }

    private static JPanel checkboxRow(JCheckBox checkbox) {
        JPanel row = optionRow();
        row.add(checkbox);
        return row;
    }

    private void saveSendToAuthentication() {
        if (updatingFromConfig) return;
        whileSaving(() -> configStore.setHandleSendToAuthentication(sendToAuthenticationCheckbox.isSelected()));
    }

    private void saveServerPings() {
        if (updatingFromConfig) return;
        whileSaving(() -> configStore.setAnswerServerPings(serverPingsCheckbox.isSelected()));
    }

    private void saveBurpNetworking() {
        if (updatingFromConfig) return;
        whileSaving(() -> configStore.setUseBurpNetworking(burpNetworkingCheckbox.isSelected()));
    }

    private void whileSaving(Runnable save) {
        savingToConfig = true;
        try {
            save.run();
        } finally {
            savingToConfig = false;
        }
    }

    private void refreshFromConfig() {
        updatingFromConfig = true;
        try {
            RedirectMode mode = configStore.redirectMode();
            if (redirectModeSelector.getSelectedItem() != mode) {
                redirectModeSelector.setSelectedItem(mode);
            }
            explainSelectedRedirectMode();
            capFields.values().forEach(ResourceCapField::refresh);
            sendToAuthenticationCheckbox.setSelected(configStore.handleSendToAuthentication());
            serverPingsCheckbox.setSelected(configStore.answerServerPings());
            burpNetworkingCheckbox.setSelected(configStore.useBurpNetworking());
        } finally {
            updatingFromConfig = false;
        }
    }

    JComboBox<RedirectMode> redirectModeSelectorForTest() {
        return redirectModeSelector;
    }

    String redirectExplanationForTest() {
        return redirectExplanation.getText();
    }

    JTextField capFieldForTest(ResourceCap cap) {
        return capFields.get(cap).field();
    }

    JLabel capStatusForTest(ResourceCap cap) {
        return capFields.get(cap).status();
    }

    JCheckBox sendToAuthenticationCheckboxForTest() {
        return sendToAuthenticationCheckbox;
    }

    JCheckBox serverPingsCheckboxForTest() {
        return serverPingsCheckbox;
    }

    JButton resetScanWarningsButtonForTest() {
        return resetScanWarningsButton;
    }

    JLabel scanWarningsStatusForTest() {
        return scanWarningsStatus;
    }

    JCheckBox burpNetworkingCheckboxForTest() {
        return burpNetworkingCheckbox;
    }

    String burpNetworkingExplanationForTest() {
        return BURP_NETWORKING_EXPLANATION;
    }

    JButton burpSettingsButtonForTest() {
        return burpSettingsButton;
    }

    JPanel burpSettingsRowForTest() {
        return burpSettingsRow;
    }

    String burpSettingsHintForTest() {
        return BURP_SETTINGS_HINT;
    }

    String sendToAuthenticationExplanationForTest() {
        return SEND_TO_AUTHENTICATION_EXPLANATION;
    }
}
