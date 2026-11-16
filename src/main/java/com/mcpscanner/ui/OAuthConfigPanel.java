package com.mcpscanner.ui;

import com.mcpscanner.ui.widgets.DialogOwner;
import com.mcpscanner.ui.widgets.Contrast;
import com.mcpscanner.ui.widgets.Edt;
import com.mcpscanner.ui.widgets.FadedWhenDisabled;
import com.mcpscanner.ui.widgets.LabelledRenderer;
import com.mcpscanner.ui.widgets.ThemeColors;
import com.mcpscanner.ui.widgets.WrappingText;
import com.mcpscanner.auth.OAuthAuthCodeStrategy;
import com.mcpscanner.auth.oauth.OAuthAuthorizationFlow;
import com.mcpscanner.auth.oauth.OAuthClientHints;
import com.mcpscanner.auth.oauth.OAuthSession;
import com.mcpscanner.scan.request.AdvertisedAuthorizationServer;
import com.mcpscanner.auth.oauth.discovery.AuthRequirement;
import com.mcpscanner.client.TransportType;
import com.mcpscanner.auth.oauth.discovery.DiscoveredMetadata;
import com.mcpscanner.auth.oauth.discovery.DiscoveryFailedException;
import com.nimbusds.oauth2.sdk.as.AuthorizationServerMetadata;
import com.mcpscanner.config.ExtensionConfigStore;
import com.mcpscanner.logging.McpEventLog;
import com.mcpscanner.ui.state.ConnectionStatus;
import com.mcpscanner.ui.widgets.DocumentChanges;
import com.mcpscanner.ui.widgets.LabeledForm;
import com.mcpscanner.core.oauth.RegistrationMode;

import javax.swing.*;
import java.awt.BorderLayout;
import java.awt.Color;
import java.awt.Font;
import java.net.URI;
import java.time.Clock;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import java.util.function.Supplier;

public class OAuthConfigPanel extends JPanel implements OAuthConnectSupport {

    private volatile AdvertisedAuthorizationServer authorizationServerOfLastDance = AdvertisedAuthorizationServer.none();

    private static final double LOCKED_FADE = 0.55;

    private final JTextField oauthIssuerField = new JTextField(30);
    private final ScopeTablePanel scopeTablePanel = new ScopeTablePanel();
    private final JSpinner oauthRedirectPortSpinner = new JSpinner(new SpinnerNumberModel(
            OAuthClientHints.DEFAULT_REDIRECT_PORT, 0, 65535, 1));
    private final JComboBox<RegistrationMode> registrationModeSelector = new JComboBox<>(RegistrationMode.values());
    private final JTextField clientMetadataUrlField = new JTextField(30);
    private final JTextField oauthClientIdField = new JTextField(20);
    private final JPasswordField oauthClientSecretField = new JPasswordField(20);
    private LabeledForm.Row clientIdRow;
    private LabeledForm.Row clientSecretRow;
    private LabeledForm.Row clientMetadataUrlRow;
    private LabeledForm.Row redirectPortRow;
    private final WrappingText registrationWarningLabel = new WrappingText("");
    private Runnable changeListener = () -> { };

    private final WrappingText discoveryStatusLabel = new WrappingText("");
    private final WrappingText registrationRequirementLabel = new WrappingText("").muted();
    private final JButton discoverButton = new JButton("Discover");


    private final OAuthAuthorizationFlow authorizationFlow;
    private final OAuthDiscoveryPresenter discoveryPresenter;
    private final Runnable signInAttemptStart;
    private final DialogOwner dialogOwner;
    private final DiscoveryViewAdapter discoveryView = new DiscoveryViewAdapter();
    private volatile OAuthAuthCodeStrategy oauthStrategy;
    private Supplier<String> endpointSupplier = () -> "";
    private boolean configurationLocked;
    private ExtensionConfigStore configStore;
    private DcrRegistrations dcrRegistrations;
    private boolean applyingDiscoveryUpdate;
    private boolean issuerAutoDiscovered;
    private boolean scopesAutoDiscovered;
    private boolean loadingSettings;
    private String clientIssuer;

    OAuthConfigPanel(OAuthAuthorizationFlow authorizationFlow, OAuthDiscoveryPresenter discoveryPresenter,
                     DialogOwner dialogOwner) {
        this(authorizationFlow, discoveryPresenter, () -> { }, dialogOwner);
    }

    OAuthConfigPanel(OAuthAuthorizationFlow authorizationFlow, OAuthDiscoveryPresenter discoveryPresenter,
                     Runnable signInAttemptStart, DialogOwner dialogOwner) {
        super(new BorderLayout());
        this.dialogOwner = Objects.requireNonNull(dialogOwner, "dialogOwner");
        this.authorizationFlow = authorizationFlow;
        this.discoveryPresenter = discoveryPresenter;
        this.signInAttemptStart = signInAttemptStart;
        describeInputs();
        fadeWhenLocked();
        layoutOauthCard();
        wireListeners();
        refreshRegistrationInputs();
        refreshDiscoverEnabled();
    }

    private void fadeWhenLocked() {
        List.of(oauthIssuerField, clientMetadataUrlField, oauthClientIdField, oauthClientSecretField)
                .forEach(FadedWhenDisabled::install);
        FadedWhenDisabled.install(registrationModeSelector);
        FadedWhenDisabled.install(discoverButton);
    }

    private void describeInputs() {
        registrationModeSelector.setRenderer(LabelledRenderer.of(RegistrationMode.class, RegistrationModeText::label));
        discoverButton.setToolTipText("Auto-discover OAuth issuer and scopes from the endpoint (RFC 9728)");
        clientMetadataUrlField.setToolTipText("Public HTTPS URL of the client metadata document; "
                + "it must list http://127.0.0.1:<redirect port>/callback");
        oauthRedirectPortSpinner.setToolTipText("Local OAuth callback port; 0 picks a free port");
        registrationWarningLabel.setForeground(ThemeColors.error());
        registrationWarningLabel.setVisible(false);
    }

    private void wireListeners() {
        registrationModeSelector.addActionListener(e -> {
            refreshRegistrationInputs();
            changeListener.run();
        });
        oauthClientIdField.getDocument().addDocumentListener(DocumentChanges.onChange(this::onClientIdChanged));
        wireInputChangeListeners();
        discoverButton.addActionListener(e -> discoverOauthMetadata(endpointSupplier.get()));
    }

    void bindConfigStore(ExtensionConfigStore configStore) {
        this.configStore = configStore;
        this.dcrRegistrations = new DcrRegistrations(configStore);
        loadingSettings = true;
        try {
            seedFromConfig(configStore);
        } finally {
            loadingSettings = false;
        }
        attachPersistenceListeners(configStore);
        onRegistrationInputsChanged();
    }

    @Override
    public void beginSignInAttempt() {
        signInAttemptStart.run();
    }

    @Override
    public OAuthAuthCodeStrategy completeOAuthDance(OAuthClientHints hints, URI mcpResource, McpEventLog eventLog) {
        return completeOAuthDance(hints, mcpResource, eventLog, null);
    }

    @Override
    public OAuthAuthCodeStrategy completeOAuthDance(OAuthClientHints hints, URI mcpResource,
                                                    McpEventLog eventLog,
                                                    AuthorizationServerMetadata preDiscovered) {
        OAuthSession session = authorizationFlow.connect(mcpResource, hints, preDiscovered);
        authorizationServerOfLastDance = session::registrationEndpoint;
        persistDcrCredentials(hints.issuer(), session);
        return new OAuthAuthCodeStrategy(
                hints.issuer(),
                session.clientId(),
                session.sharedSession(),
                Clock.systemUTC(),
                eventLog,
                new OAuthScopeApproval(dialogOwner, this, hints.issuer(), mcpResource, session.clientId(), eventLog::warn)::approve,
                session.registrationMode());
    }

    private void persistDcrCredentials(URI issuer, OAuthSession session) {
        if (dcrRegistrations != null) {
            dcrRegistrations.remember(issuer, session);
        }
    }

    @Override
    public AdvertisedAuthorizationServer authorizationServerOfLastDance() {
        return authorizationServerOfLastDance;
    }

    @Override
    public void publishOauthStrategy(OAuthAuthCodeStrategy strategy) {
        this.oauthStrategy = strategy;
    }

    void applyClientHints(OAuthClientHints hints) {
        oauthIssuerField.setText(textOf(hints.issuer()));
        registrationModeSelector.setSelectedItem(hints.registrationMode());
        oauthClientIdField.setText(Objects.toString(hints.clientId(), ""));
        oauthClientSecretField.setText(Objects.toString(hints.clientSecret(), ""));
        clientMetadataUrlField.setText(textOf(hints.clientMetadataUrl()));
        oauthRedirectPortSpinner.setValue(hints.redirectPort());
        scopeTablePanel.seed(hints.scopes().stream().map(ScopeTableModel::customScope).toList());
        onClientIdChanged();
    }

    private static String textOf(URI uri) {
        return uri == null ? "" : uri.toString();
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

    Optional<DiscoveredMetadata> lastDiscoveryFor(URI endpoint) {
        return discoveryPresenter.lastDiscoveryFor(endpoint);
    }

    @Override
    public AuthRequirement probeAuthRequirement(String endpoint, TransportType transport) {
        return discoveryPresenter.probeSync(URI.create(endpoint), transport);
    }

    @Override
    public void applyDiscoveredMetadata(DiscoveredMetadata metadata) {
        Edt.run(() -> populateFromDiscoveredMetadata(metadata, metadata.selectedScopes()));
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
        oauthIssuerField.setEnabled(!locked);
        scopeTablePanel.setLocked(locked);
        registrationModeSelector.setEnabled(!locked);
        oauthRedirectPortSpinner.setEnabled(!locked);
        fadePortText();
        refreshRegistrationInputs();
        refreshDiscoverEnabled();
    }

    private void fadePortText() {
        JTextField port = ((JSpinner.DefaultEditor) oauthRedirectPortSpinner.getEditor()).getTextField();
        port.setDisabledTextColor(Contrast.blend(port.getForeground(), port.getBackground(), LOCKED_FADE));
    }

    ScopeTablePanel scopeTable() {
        return scopeTablePanel;
    }

    void setChangeListener(Runnable changeListener) {
        this.changeListener = changeListener;
    }

    Validated<OAuthClientHints> validatedHints() {
        return Validated.of(this::buildOauthHints);
    }

    private void wireInputChangeListeners() {
        Runnable onInputChange = this::onRegistrationInputsChanged;
        oauthIssuerField.getDocument().addDocumentListener(DocumentChanges.onChange(onInputChange));
        clientMetadataUrlField.getDocument().addDocumentListener(DocumentChanges.onChange(onInputChange));
        oauthRedirectPortSpinner.addChangeListener(e -> onInputChange.run());
    }

    private void onRegistrationInputsChanged() {
        refreshRegistrationWarning();
        changeListener.run();
    }

    private void refreshRegistrationWarning() {
        boolean ignored = registrationForm().clientIdIgnored();
        registrationWarningLabel.setText(ignored ? "Client ID is ignored until it is re-entered for this issuer." : "");
        registrationWarningLabel.setVisible(ignored);
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
        Edt.run(this::doClearAutoDiscoveredOAuth);
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
        registrationModeSelector.setSelectedItem(configStore.oauthRegistrationMode());
        clientMetadataUrlField.setText(configStore.oauthClientMetadataUrl());
        String savedClientId = configStore.oauthClientId();
        if (savedClientId != null) {
            oauthClientIdField.setText(savedClientId);
        }
        clientIssuer = configStore.oauthClientIssuer();
        scopeTablePanel.seed(configStore.scopes());
    }

    private void attachPersistenceListeners(ExtensionConfigStore configStore) {
        oauthIssuerField.getDocument().addDocumentListener(DocumentChanges.onChange(this::onIssuerFieldChanged));
        oauthRedirectPortSpinner.addChangeListener(
                e -> configStore.setOauthRedirectPort((Integer) oauthRedirectPortSpinner.getValue()));
        registrationModeSelector.addActionListener(
                e -> configStore.setOauthRegistrationMode(registrationMode()));
        clientMetadataUrlField.getDocument().addDocumentListener(
                DocumentChanges.onChange(() -> configStore.setOauthClientMetadataUrl(clientMetadataUrlField.getText())));
        scopeTablePanel.setOnChange(this::onScopesChanged);
    }

    private void onClientIdChanged() {
        if (loadingSettings) {
            return;
        }
        clientIssuer = oauthIssuerField.getText().trim();
        if (configStore != null) {
            configStore.setOauthClientId(oauthClientIdField.getText());
            configStore.setOauthClientIssuer(clientIssuer);
        }
        onRegistrationInputsChanged();
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

    JTextField getOauthIssuerField() {
        return oauthIssuerField;
    }

    JComboBox<RegistrationMode> getRegistrationModeSelector() {
        return registrationModeSelector;
    }

    JTextField getClientMetadataUrlField() {
        return clientMetadataUrlField;
    }

    JSpinner getRedirectPortSpinner() {
        return oauthRedirectPortSpinner;
    }

    JTextField getOauthClientIdField() {
        return oauthClientIdField;
    }

    WrappingText getDiscoveryStatusLabel() {
        return discoveryStatusLabel;
    }

    JButton getDiscoverButton() {
        return discoverButton;
    }

    @Override
    public OAuthAuthCodeStrategy currentOauthStrategy() {
        return oauthStrategy;
    }

    private void layoutOauthCard() {
        LabeledForm form = OAuthForms.cardForm();
        form.addRow("Issuer URL:", buildIssuerWithDiscover());
        form.addUnlabeledRow(discoveryStatusLabel);
        form.addRow("Scopes:", scopeTablePanel);
        form.addRow("Registration:", registrationModeSelector);
        form.addUnlabeledRow(registrationRequirementLabel);
        form.addUnlabeledRow(registrationWarningLabel);
        clientIdRow = form.addRow("Client ID:", oauthClientIdField);
        clientSecretRow = form.addRow("Client secret:", oauthClientSecretField);
        clientMetadataUrlRow = form.addRow("Metadata URL:", clientMetadataUrlField);
        redirectPortRow = form.addCompactRow("Redirect port:", oauthRedirectPortSpinner);
        form.keepRowsAtTop();
        add(form, BorderLayout.NORTH);
    }

    private JPanel buildIssuerWithDiscover() {
        JPanel row = new JPanel(new BorderLayout(8, 0));
        row.add(oauthIssuerField, BorderLayout.CENTER);
        row.add(discoverButton, BorderLayout.EAST);
        return row;
    }

    Optional<DcrRegistrations.Registration> registrationFor(URI issuer) {
        return dcrRegistrations == null || issuer == null ? Optional.empty()
                : dcrRegistrations.forIssuer(issuer.toString());
    }

    private void refreshDiscoverEnabled() {
        boolean endpointPresent = !endpointSupplier.get().trim().isEmpty();
        boolean inFlight = discoveryPresenter != null && discoveryPresenter.isDiscoveryInFlight();
        discoverButton.setEnabled(!configurationLocked && !inFlight && endpointPresent);
    }

    private void renderDiscoveryStatus(String text, Color color, int fontStyle) {
        discoveryStatusLabel.setText(text);
        discoveryStatusLabel.setForeground(color);
        discoveryStatusLabel.setFont(discoveryStatusLabel.getFont().deriveFont(fontStyle));
    }

    private final class DiscoveryViewAdapter implements OAuthDiscoveryPresenter.View {
        @Override
        public void onDiscoveryInFlight() {
            renderDiscoveryStatus("Discovering...", ThemeColors.muted(), Font.ITALIC);
            discoverButton.setEnabled(false);
        }

        @Override
        public void onDiscoverySuccess(DiscoveredMetadata metadata, List<String> selectedScopes) {
            populateFromDiscoveredMetadata(metadata, selectedScopes);
        }

        @Override
        public void onDiscoveryFailure() {
            renderDiscoveryStatus("No OAuth metadata found — enter issuer manually", ThemeColors.error(), Font.PLAIN);
            refreshDiscoverEnabled();
        }

        @Override
        public void onDiscoveryInvalidUrl(String detail) {
            String suffix = detail == null || detail.isBlank() ? "" : ": " + detail;
            renderDiscoveryStatus("Invalid endpoint URL" + suffix, ThemeColors.error(), Font.PLAIN);
        }
    }

    private void populateFromDiscoveredMetadata(DiscoveredMetadata metadata, List<String> selectedScopes) {
        applyingDiscoveryUpdate = true;
        try {
            oauthIssuerField.setText(metadata.issuer().toString());
            scopeTablePanel.replaceDiscovered(selectedScopes);
        } finally {
            applyingDiscoveryUpdate = false;
        }
        renderDiscoveryStatus("Discovered from " + metadata.source().displayPath(), ThemeColors.muted(), Font.PLAIN);
        refreshDiscoverEnabled();
    }

    private OAuthClientHints buildOauthHints() {
        return registrationForm().hints();
    }

    private OAuthRegistrationForm registrationForm() {
        return new OAuthRegistrationForm(oauthIssuerField.getText(), scopeTablePanel.enabledScopes(),
                registrationMode(), oauthClientIdField.getText(), new String(oauthClientSecretField.getPassword()),
                clientIssuer, clientMetadataUrlField.getText(), (Integer) oauthRedirectPortSpinner.getValue());
    }

    private RegistrationMode registrationMode() {
        return (RegistrationMode) registrationModeSelector.getSelectedItem();
    }

    private void refreshRegistrationInputs() {
        RegistrationMode mode = registrationMode();
        boolean usesClient = OAuthRegistrationForm.usesClient(mode);
        boolean usesMetadataDocument = OAuthRegistrationForm.usesMetadataDocument(mode);
        oauthClientIdField.setEnabled(!configurationLocked && usesClient);
        oauthClientSecretField.setEnabled(!configurationLocked && usesClient);
        clientMetadataUrlField.setEnabled(!configurationLocked && usesMetadataDocument);
        registrationRequirementLabel.setText(RegistrationModeText.requirement(mode));
        clientIdRow.setRequired(mode == RegistrationMode.PRE_REGISTERED);
        clientMetadataUrlRow.setRequired(mode == RegistrationMode.CIMD);
        redirectPortRow.setRequired(mode == RegistrationMode.CIMD);
        refreshRegistrationWarning();
        clientIdRow.setVisible(usesClient);
        clientSecretRow.setVisible(usesClient);
        clientMetadataUrlRow.setVisible(usesMetadataDocument);
        revalidate();
    }
}
