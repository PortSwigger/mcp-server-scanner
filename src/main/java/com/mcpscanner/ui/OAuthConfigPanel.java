package com.mcpscanner.ui;

import com.mcpscanner.auth.OAuthAuthCodeStrategy;
import com.mcpscanner.auth.oauth.OAuthAuthorizationFlow;
import com.mcpscanner.auth.oauth.OAuthClientHints;
import com.mcpscanner.auth.oauth.OAuthSession;
import com.mcpscanner.auth.oauth.discovery.DiscoveredMetadata;
import com.mcpscanner.auth.oauth.discovery.DiscoveryFailedException;
import com.mcpscanner.config.ExtensionConfigStore;
import com.mcpscanner.logging.McpEventLog;
import com.mcpscanner.ui.state.ConnectionStatus;
import com.mcpscanner.ui.widgets.ScopeTablePanel;

import javax.swing.*;
import javax.swing.event.DocumentEvent;
import javax.swing.event.DocumentListener;
import java.awt.Color;
import java.awt.Component;
import java.awt.Dimension;
import java.awt.Font;
import java.awt.FlowLayout;
import java.awt.GridBagConstraints;
import java.awt.GridBagLayout;
import java.awt.Insets;
import java.awt.Toolkit;
import java.awt.datatransfer.StringSelection;
import java.net.URI;
import java.time.Clock;
import java.util.List;
import java.util.function.Supplier;

public class OAuthConfigPanel extends JPanel implements OAuthConnectSupport {

    private final JTextField oauthIssuerField;
    private final ScopeTablePanel scopeTablePanel;
    private final JSpinner oauthRedirectPortSpinner;
    private final JCheckBox oauthSkipDcrCheckbox;
    private final JTextField oauthClientIdField;
    private final JPasswordField oauthClientSecretField;
    private final JPanel oauthManualClientPanel;

    private final JLabel discoveryStatusLabel;
    private final JButton discoverButton;
    private final JLabel discoverCaption;

    private final JPanel dcrManagementPanel;
    private final JTextField dcrClientUriField;
    private final JButton copyMgmtTokenButton;

    private final OAuthAuthorizationFlow authorizationFlow;
    private final OAuthDiscoveryPresenter discoveryPresenter;
    private final DiscoveryViewAdapter discoveryView = new DiscoveryViewAdapter();
    private volatile OAuthAuthCodeStrategy oauthStrategy;
    private Supplier<String> endpointSupplier = () -> "";
    private boolean configurationLocked;
    private boolean oauthSelected = true;
    private ExtensionConfigStore configStore;
    private boolean applyingDiscoveryUpdate;
    private boolean issuerAutoDiscovered;
    private boolean scopesAutoDiscovered;

    OAuthConfigPanel(OAuthAuthorizationFlow authorizationFlow, OAuthDiscoveryPresenter discoveryPresenter) {
        this.authorizationFlow = authorizationFlow;
        this.discoveryPresenter = discoveryPresenter;
        setLayout(new GridBagLayout());

        oauthIssuerField = new JTextField(30);
        scopeTablePanel = new ScopeTablePanel();
        oauthRedirectPortSpinner = new JSpinner(new SpinnerNumberModel(
                OAuthClientHints.DEFAULT_REDIRECT_PORT, 0, 65535, 1));
        oauthSkipDcrCheckbox = new JCheckBox("Skip DCR (use manual client_id / client_secret)");
        oauthClientIdField = new JTextField(20);
        oauthClientSecretField = new JPasswordField(20);
        oauthManualClientPanel = buildOauthManualClientPanel();
        discoveryStatusLabel = new JLabel(" ");
        discoverButton = new JButton("Discover");
        discoverCaption = buildDiscoverCaption();
        dcrClientUriField = new JTextField(30);
        dcrClientUriField.setEditable(false);
        copyMgmtTokenButton = new JButton("Copy mgmt token");
        copyMgmtTokenButton.addActionListener(e -> copyMgmtTokenToClipboard());
        dcrManagementPanel = buildDcrManagementPanel();

        layoutOauthCard();

        oauthSkipDcrCheckbox.addActionListener(
                e -> oauthManualClientPanel.setVisible(oauthSkipDcrCheckbox.isSelected()));
        discoverButton.addActionListener(e -> discoverOauthMetadata(endpointSupplier.get()));
        refreshDiscoverEnabled();
    }

    void bindConfigStore(ExtensionConfigStore configStore) {
        this.configStore = configStore;
        seedFromConfig(configStore);
        attachPersistenceListeners(configStore);
    }

    @Override
    public OAuthAuthCodeStrategy completeOAuthDance(OAuthClientHints hints, URI mcpResource, McpEventLog eventLog) {
        OAuthSession session = authorizationFlow.connect(mcpResource, hints);
        persistDcrCredentials(hints.issuer(), session);
        return new OAuthAuthCodeStrategy(
                hints.issuer(),
                hints.scopes(),
                session.clientId(),
                session.clientSecret(),
                mcpResource,
                session.tokens(),
                authorizationFlow::refresh,
                Clock.systemUTC(),
                eventLog);
    }

    private void persistDcrCredentials(URI issuer, OAuthSession session) {
        if (configStore == null || issuer == null) {
            return;
        }
        String issuerStr = issuer.toString();
        boolean hasDcrCredentials = session.registrationAccessToken().isPresent();
        session.registrationAccessToken().ifPresent(
                tok -> configStore.setDcrRegistrationManagementToken(issuerStr, tok));
        session.registrationClientUri().ifPresent(
                uri -> configStore.setDcrRegistrationClientUri(issuerStr, uri));
        if (hasDcrCredentials) {
            SwingUtilities.invokeLater(this::refreshDcrManagementPanel);
        }
    }

    @Override
    public void publishOauthStrategy(OAuthAuthCodeStrategy strategy) {
        this.oauthStrategy = strategy;
    }

    @Override
    public OAuthClientHints buildOauthHintsSnapshot() {
        return buildOauthHints();
    }

    public void discoverOauthMetadata(String endpoint) {
        discoveryPresenter.discoverMetadata(discoveryView, endpoint);
        refreshDiscoverEnabled();
    }

    @Override
    public DiscoveredMetadata discoverOauthMetadataSync(String endpoint) throws DiscoveryFailedException {
        return discoveryPresenter.discoverSync(URI.create(endpoint));
    }

    @Override
    public void applyDiscoveredMetadata(DiscoveredMetadata metadata) {
        Runnable populate = () -> populateFromDiscoveredMetadata(metadata, metadata.advertisedScopes());
        if (SwingUtilities.isEventDispatchThread()) {
            populate.run();
        } else {
            SwingUtilities.invokeLater(populate);
        }
    }

    void setEndpointSupplier(Supplier<String> supplier) {
        this.endpointSupplier = supplier != null ? supplier : () -> "";
        refreshDiscoverEnabled();
    }

    void onEndpointChanged() {
        refreshDiscoverEnabled();
    }

    void setConfigurationLocked(boolean locked) {
        configurationLocked = locked;
        refreshDiscoverEnabled();
    }

    void setOauthSelected(boolean selected) {
        this.oauthSelected = selected;
        refreshDiscoverEnabled();
    }

    @Override
    public ConnectionStatus buildConnectedStatus(String host, int toolCount) {
        return discoveryPresenter.buildConnectedStatus(oauthStrategy, host, toolCount);
    }

    void shutdown() {
        discoveryPresenter.shutdown();
    }

    @Override
    public void clearOauthStrategy() {
        oauthStrategy = null;
    }

    @Override
    public void clearAutoDiscoveredOAuth() {
        if (SwingUtilities.isEventDispatchThread()) {
            doClearAutoDiscoveredOAuth();
        } else {
            SwingUtilities.invokeLater(this::doClearAutoDiscoveredOAuth);
        }
    }

    private void doClearAutoDiscoveredOAuth() {
        applyingDiscoveryUpdate = true;
        try {
            if (issuerAutoDiscovered) {
                oauthIssuerField.setText("");
                if (configStore != null) {
                    configStore.setOauthIssuer("");
                }
                issuerAutoDiscovered = false;
            }
            if (scopesAutoDiscovered) {
                scopeTablePanel.removeDiscovered();
                scopesAutoDiscovered = false;
            }
        } finally {
            applyingDiscoveryUpdate = false;
        }
    }

    private void seedFromConfig(ExtensionConfigStore configStore) {
        String savedIssuer = configStore.oauthIssuer();
        if (savedIssuer != null) {
            oauthIssuerField.setText(savedIssuer);
        }
        oauthRedirectPortSpinner.setValue(configStore.oauthRedirectPort());
        oauthSkipDcrCheckbox.setSelected(configStore.oauthSkipDcr());
        oauthManualClientPanel.setVisible(oauthSkipDcrCheckbox.isSelected());
        String savedClientId = configStore.oauthClientId();
        if (savedClientId != null) {
            oauthClientIdField.setText(savedClientId);
        }
        scopeTablePanel.seed(configStore.scopes());
        refreshDcrManagementPanel();
    }

    private void attachPersistenceListeners(ExtensionConfigStore configStore) {
        oauthIssuerField.getDocument().addDocumentListener(onTextChange(this::onIssuerFieldChanged));
        oauthRedirectPortSpinner.addChangeListener(
                e -> configStore.setOauthRedirectPort((Integer) oauthRedirectPortSpinner.getValue()));
        oauthSkipDcrCheckbox.addActionListener(
                e -> configStore.setOauthSkipDcr(oauthSkipDcrCheckbox.isSelected()));
        oauthClientIdField.getDocument().addDocumentListener(
                onTextChange(() -> configStore.setOauthClientId(oauthClientIdField.getText())));
        scopeTablePanel.setOnChange(this::onScopesChanged);
    }

    private void onIssuerFieldChanged() {
        if (applyingDiscoveryUpdate) {
            issuerAutoDiscovered = true;
            return;
        }
        issuerAutoDiscovered = false;
        if (configStore != null) {
            configStore.setOauthIssuer(oauthIssuerField.getText());
        }
        refreshDcrManagementPanel();
    }

    private void onScopesChanged() {
        if (applyingDiscoveryUpdate) {
            scopesAutoDiscovered = true;
            return;
        }
        if (configStore != null) {
            configStore.setScopes(scopeTablePanel.customScopesSnapshot());
        }
    }

    private static DocumentListener onTextChange(Runnable callback) {
        return new DocumentListener() {
            @Override
            public void insertUpdate(DocumentEvent e) {
                callback.run();
            }

            @Override
            public void removeUpdate(DocumentEvent e) {
                callback.run();
            }

            @Override
            public void changedUpdate(DocumentEvent e) {
                callback.run();
            }
        };
    }

    JTextField getOauthIssuerField() {
        return oauthIssuerField;
    }

    JCheckBox getOauthSkipDcrCheckbox() {
        return oauthSkipDcrCheckbox;
    }

    JTextField getOauthClientIdField() {
        return oauthClientIdField;
    }

    JLabel getDiscoveryStatusLabel() {
        return discoveryStatusLabel;
    }

    JButton getDiscoverButton() {
        return discoverButton;
    }

    @Override
    public OAuthAuthCodeStrategy currentOauthStrategy() {
        return oauthStrategy;
    }

    ScopeTablePanel scopeTablePanelForTest() {
        return scopeTablePanel;
    }

    void setOauthStrategyForTest(OAuthAuthCodeStrategy strategy) {
        this.oauthStrategy = strategy;
    }

    private void layoutOauthCard() {
        GridBagConstraints gbc = createDefaultConstraints();

        addNestedRow(this, gbc, 0, "Issuer URL:", buildIssuerWithDiscover());
        addNestedRow(this, gbc, 1, "", discoverCaption);
        addNestedRow(this, gbc, 2, "", discoveryStatusLabel);
        addNestedExpandingRow(this, gbc, 3, "Scopes:", scopeTablePanel);
        addNestedRow(this, gbc, 4, "Redirect Port:", buildRedirectPortRow());
        addNestedRow(this, gbc, 5, "", oauthSkipDcrCheckbox);

        oauthManualClientPanel.setVisible(false);
        addNestedRow(this, gbc, 6, "", oauthManualClientPanel);
        addNestedRow(this, gbc, 7, "", dcrManagementPanel);
    }

    private JPanel buildRedirectPortRow() {
        JPanel row = new JPanel(new FlowLayout(FlowLayout.LEFT, 0, 0));
        oauthRedirectPortSpinner.setPreferredSize(
                new Dimension(96, oauthRedirectPortSpinner.getPreferredSize().height));
        row.add(oauthRedirectPortSpinner);
        return row;
    }

    private JPanel buildIssuerWithDiscover() {
        JPanel row = new JPanel();
        row.setLayout(new BoxLayout(row, BoxLayout.LINE_AXIS));
        oauthIssuerField.setMaximumSize(
                new Dimension(Integer.MAX_VALUE, oauthIssuerField.getPreferredSize().height));
        row.add(oauthIssuerField);
        row.add(Box.createHorizontalStrut(8));
        row.add(discoverButton);
        return row;
    }

    private JLabel buildDiscoverCaption() {
        JLabel caption = new JLabel("Auto-discover OAuth issuer & scopes (RFC 9728)");
        caption.setForeground(Color.GRAY);
        caption.setFont(caption.getFont().deriveFont(caption.getFont().getSize2D() - 1f));
        return caption;
    }

    private JPanel buildOauthManualClientPanel() {
        JPanel panel = new JPanel(new GridBagLayout());
        GridBagConstraints gbc = createDefaultConstraints();
        addNestedRow(panel, gbc, 0, "Client ID:", oauthClientIdField);
        addNestedRow(panel, gbc, 1, "Client Secret:", oauthClientSecretField);
        return panel;
    }

    private JPanel buildDcrManagementPanel() {
        JPanel panel = new JPanel(new GridBagLayout());
        panel.setBorder(BorderFactory.createTitledBorder("DCR Management"));
        GridBagConstraints gbc = createDefaultConstraints();
        addNestedRow(panel, gbc, 0, "Client URI:", dcrClientUriField);
        addNestedRow(panel, gbc, 1, "", copyMgmtTokenButton);
        panel.setVisible(false);
        return panel;
    }

    private void copyMgmtTokenToClipboard() {
        if (configStore == null) {
            return;
        }
        String issuer = oauthIssuerField.getText().trim();
        if (issuer.isEmpty()) {
            return;
        }
        String token = configStore.dcrRegistrationManagementToken(issuer);
        if (token == null || token.isBlank()) {
            return;
        }
        Toolkit.getDefaultToolkit().getSystemClipboard()
                .setContents(new StringSelection(token), null);
    }

    void refreshDcrManagementPanel() {
        if (configStore == null) {
            dcrManagementPanel.setVisible(false);
            return;
        }
        String issuer = oauthIssuerField.getText().trim();
        if (issuer.isEmpty()) {
            dcrManagementPanel.setVisible(false);
            return;
        }
        String token = configStore.dcrRegistrationManagementToken(issuer);
        String uri = configStore.dcrRegistrationClientUri(issuer);
        boolean hasCredentials = token != null && !token.isBlank();
        if (hasCredentials) {
            dcrClientUriField.setText(uri != null ? uri : "");
        }
        dcrManagementPanel.setVisible(hasCredentials);
    }

    private void refreshDiscoverEnabled() {
        boolean endpointPresent = !endpointSupplier.get().trim().isEmpty();
        boolean inFlight = discoveryPresenter != null && discoveryPresenter.isDiscoveryInFlight();
        discoverButton.setEnabled(oauthSelected && !configurationLocked && !inFlight && endpointPresent);
    }

    private void renderDiscoveryStatus(String text, Color color, int fontStyle) {
        discoveryStatusLabel.setText(text);
        discoveryStatusLabel.setForeground(color);
        discoveryStatusLabel.setFont(discoveryStatusLabel.getFont().deriveFont(fontStyle));
    }

    private final class DiscoveryViewAdapter implements OAuthDiscoveryPresenter.View {
        @Override
        public void onDiscoveryInFlight() {
            renderDiscoveryStatus("Discovering...", Color.GRAY, Font.ITALIC);
            discoverButton.setEnabled(false);
        }

        @Override
        public void onDiscoverySuccess(DiscoveredMetadata metadata, List<String> advertisedScopes) {
            populateFromDiscoveredMetadata(metadata, advertisedScopes);
        }

        @Override
        public void onDiscoveryFailure() {
            renderDiscoveryStatus("No OAuth metadata found — enter issuer manually", Color.RED, Font.PLAIN);
            refreshDiscoverEnabled();
        }

        @Override
        public void onDiscoveryInvalidUrl(String detail) {
            String suffix = detail == null || detail.isBlank() ? "" : ": " + detail;
            renderDiscoveryStatus("Invalid endpoint URL" + suffix, Color.RED, Font.PLAIN);
        }
    }

    private void populateFromDiscoveredMetadata(DiscoveredMetadata metadata, List<String> advertisedScopes) {
        applyingDiscoveryUpdate = true;
        try {
            oauthIssuerField.setText(metadata.issuer().toString());
            scopeTablePanel.replaceDiscovered(advertisedScopes);
        } finally {
            applyingDiscoveryUpdate = false;
        }
        renderDiscoveryStatus("Discovered from " + metadata.source().displayPath(), Color.GRAY, Font.PLAIN);
        refreshDiscoverEnabled();
    }

    private OAuthClientHints buildOauthHints() {
        String issuer = oauthIssuerField.getText().trim();
        URI issuerUri = issuer.isEmpty() ? null : URI.create(issuer);
        boolean skipDcr = oauthSkipDcrCheckbox.isSelected();
        String clientId = skipDcr ? oauthClientIdField.getText().trim() : null;
        String clientSecret = skipDcr
                ? new String(oauthClientSecretField.getPassword()).trim()
                : null;
        if (clientSecret != null && clientSecret.isEmpty()) {
            clientSecret = null;
        }
        if (skipDcr && (clientId == null || clientId.isEmpty())) {
            throw new IllegalArgumentException("Client ID is required when DCR is skipped");
        }
        int redirectPort = (Integer) oauthRedirectPortSpinner.getValue();
        return new OAuthClientHints(
                issuerUri,
                scopeTablePanel.enabledScopes(),
                clientId,
                clientSecret,
                !skipDcr,
                redirectPort,
                OAuthClientHints.DEFAULT_TIMEOUT);
    }

    private void addNestedRow(JPanel panel, GridBagConstraints gbc, int row, String label, Component component) {
        gbc.gridx = 0;
        gbc.gridy = row;
        gbc.weightx = 0;
        gbc.fill = GridBagConstraints.NONE;
        panel.add(new JLabel(label), gbc);

        gbc.gridx = 1;
        gbc.weightx = 1.0;
        gbc.fill = GridBagConstraints.HORIZONTAL;
        panel.add(component, gbc);
    }

    private void addNestedExpandingRow(JPanel panel, GridBagConstraints gbc, int row, String label, Component component) {
        gbc.gridx = 0;
        gbc.gridy = row;
        gbc.weightx = 0;
        gbc.weighty = 0;
        gbc.fill = GridBagConstraints.NONE;
        gbc.anchor = GridBagConstraints.NORTHWEST;
        panel.add(new JLabel(label), gbc);

        gbc.gridx = 1;
        gbc.weightx = 1.0;
        gbc.weighty = 1.0;
        gbc.fill = GridBagConstraints.BOTH;
        panel.add(component, gbc);

        gbc.weighty = 0;
        gbc.anchor = GridBagConstraints.WEST;
    }

    private GridBagConstraints createDefaultConstraints() {
        GridBagConstraints gbc = new GridBagConstraints();
        gbc.insets = new Insets(4, 4, 4, 4);
        gbc.anchor = GridBagConstraints.WEST;
        return gbc;
    }
}
