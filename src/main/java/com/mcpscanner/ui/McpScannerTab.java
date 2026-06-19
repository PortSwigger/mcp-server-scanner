package com.mcpscanner.ui;

import burp.api.montoya.logging.Logging;
import burp.api.montoya.ui.UserInterface;
import com.mcpscanner.auth.AuthStrategy;
import com.mcpscanner.auth.CurrentAuthHolder;
import com.mcpscanner.auth.oauth.CallbackListener;
import com.mcpscanner.auth.oauth.OAuthAuthorizationFlow;
import com.mcpscanner.auth.oauth.OAuthClientHints;
import com.mcpscanner.checks.registry.ScanCheckRegistry;
import com.mcpscanner.checks.registry.ScanCheckSettings;
import com.mcpscanner.client.ConnectResult;
import com.mcpscanner.client.McpClientManager;
import com.mcpscanner.mcp.McpToolDefinition;
import com.mcpscanner.mcp.ServerMetadata;
import com.mcpscanner.client.TransportType;
import com.mcpscanner.config.ExtensionConfigStore;
import com.mcpscanner.logging.McpEventLog;
import com.mcpscanner.scan.CurrentSelectionHolder;
import com.mcpscanner.scan.McpScanLauncher;
import com.mcpscanner.scan.ScanInventory;
import com.mcpscanner.ui.connect.ConnectCoordinator;
import com.mcpscanner.ui.connect.ConnectionAttemptResult;
import com.mcpscanner.ui.state.Cancellable;
import com.mcpscanner.ui.state.ConnectAttempt;
import com.mcpscanner.ui.state.ConnectPhase;
import com.mcpscanner.ui.state.ConnectionStatus;
import com.mcpscanner.ui.state.UiAction;
import com.mcpscanner.ui.state.UiConnectionState;
import com.mcpscanner.ui.state.UiSideEffect;
import com.mcpscanner.ui.state.UiStateReducer;
import com.mcpscanner.ui.widgets.HyperlinkLabel;
import com.mcpscanner.ui.widgets.StatusCluster;

import javax.swing.*;
import javax.swing.event.DocumentEvent;
import javax.swing.event.DocumentListener;
import javax.swing.event.TableModelEvent;
import java.awt.BorderLayout;
import java.awt.Color;
import java.awt.Dimension;
import java.awt.FlowLayout;
import java.awt.Insets;
import java.net.URI;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.function.Function;

public class McpScannerTab extends JPanel {

    private static final int ENDPOINT_FIELD_COLUMNS = 48;
    private static final int TOOLBAR_WIDGET_HEIGHT = 32;
    private static final int SCAN_LAUNCHED_FLASH_MS = 1500;
    private static final Insets BUTTON_MARGIN = new Insets(4, 14, 4, 14);
    private static final Color PORTSWIGGER_ORANGE = new Color(0xFF6633);
    private static final Color PORTSWIGGER_ORANGE_HOVER = new Color(0xFF7F4D);
    private static final Color PORTSWIGGER_ORANGE_PRESSED = new Color(0xE65A2D);
    private static final Color PORTSWIGGER_ORANGE_DISABLED = new Color(0x8A4528);

    private final McpClientManager clientManager;
    private final McpScanLauncher scanLauncher;
    private final Logging logging;
    private final ExtensionConfigStore configStore;
    private final ScanCheckRegistry checkRegistry;
    private final ScanCheckSettings checkSettings;
    private final McpEventLog eventLog;
    private final CurrentAuthHolder authHolder;
    private final CurrentSelectionHolder selectionHolder;
    private final UiStateReducer reducer = new UiStateReducer();
    private final ConnectCoordinator connectCoordinator;

    private final ServerConfigPanel serverConfigPanel;
    private final ScanChecksPanel scanChecksPanel;
    private final InspectorPanel inspectorPanel;
    private final ToolTablePanel toolTablePanel;
    private final ResourceTablePanel resourceTablePanel;
    private final ResourceTemplateTablePanel resourceTemplateTablePanel;
    private final PromptTablePanel promptTablePanel;
    private final ServerInfoPanel serverInfoPanel;

    private final JTextField endpointField;
    private final JComboBox<TransportType> transportCombo;
    private final JComboBox<String> authTypeCombo;
    private final JButton primaryButton;
    private final JButton scanButton;
    private final StatusCluster statusCluster;

    private UiConnectionState state = UiConnectionState.disconnected();
    private AuthStrategy authStrategyOverride;
    private Function<List<McpToolDefinition>, DestructiveScanConfirmation.Result> confirmationPrompt =
            tools -> DestructiveScanConfirmation.prompt(this, tools);

    public McpScannerTab(McpClientManager clientManager, McpScanLauncher scanLauncher,
                         Logging logging, ExtensionConfigStore configStore,
                         ScanCheckRegistry checkRegistry, ScanCheckSettings checkSettings,
                         McpEventLog eventLog, CurrentAuthHolder authHolder,
                         CurrentSelectionHolder selectionHolder,
                         OAuthAuthorizationFlow authorizationFlow,
                         UserInterface userInterface) {
        this(clientManager, scanLauncher, logging, configStore, checkRegistry, checkSettings,
                eventLog, authHolder, selectionHolder, authorizationFlow, null, userInterface);
    }

    public McpScannerTab(McpClientManager clientManager, McpScanLauncher scanLauncher,
                         Logging logging, ExtensionConfigStore configStore,
                         ScanCheckRegistry checkRegistry, ScanCheckSettings checkSettings,
                         McpEventLog eventLog, CurrentAuthHolder authHolder,
                         CurrentSelectionHolder selectionHolder,
                         OAuthAuthorizationFlow authorizationFlow,
                         com.mcpscanner.auth.oauth.discovery.OAuthMetadataDiscoverer discoverer,
                         UserInterface userInterface) {
        this(clientManager, scanLauncher, logging, configStore, checkRegistry, checkSettings,
                eventLog, authHolder, selectionHolder,
                discoverer != null
                        ? new ServerConfigPanel(configStore, authorizationFlow, discoverer)
                        : new ServerConfigPanel(configStore, authorizationFlow),
                userInterface);
    }

    McpScannerTab(McpClientManager clientManager, McpScanLauncher scanLauncher,
                  Logging logging, ExtensionConfigStore configStore,
                  ScanCheckRegistry checkRegistry, ScanCheckSettings checkSettings,
                  McpEventLog eventLog, CurrentAuthHolder authHolder,
                  CurrentSelectionHolder selectionHolder,
                  ServerConfigPanel serverConfigPanel,
                  UserInterface userInterface) {
        super(new BorderLayout());
        this.clientManager = clientManager;
        this.scanLauncher = scanLauncher;
        this.logging = logging;
        this.configStore = configStore;
        this.checkRegistry = checkRegistry;
        this.checkSettings = checkSettings;
        this.eventLog = eventLog;
        this.authHolder = Objects.requireNonNull(authHolder, "authHolder must not be null");
        this.selectionHolder = Objects.requireNonNull(selectionHolder, "selectionHolder must not be null");

        this.serverConfigPanel = Objects.requireNonNull(serverConfigPanel, "serverConfigPanel must not be null");
        this.connectCoordinator = new ConnectCoordinator(serverConfigPanel, clientManager, eventLog);
        this.scanChecksPanel = new ScanChecksPanel(checkRegistry, checkSettings, logging::logToError);
        this.inspectorPanel = new InspectorPanel(serverConfigPanel, scanChecksPanel, eventLog);
        this.toolTablePanel = new ToolTablePanel(userInterface);
        this.resourceTablePanel = new ResourceTablePanel();
        this.resourceTemplateTablePanel = new ResourceTemplateTablePanel();
        this.promptTablePanel = new PromptTablePanel();
        this.serverInfoPanel = new ServerInfoPanel(userInterface);

        this.endpointField = new JTextField(ENDPOINT_FIELD_COLUMNS);
        this.transportCombo = new JComboBox<>(TransportType.values());
        this.authTypeCombo = new JComboBox<>(ServerConfigPanel.AUTH_TYPES.toArray(new String[0]));
        this.primaryButton = createToolbarButton(state.status().primaryButtonLabel());
        this.scanButton = createToolbarButton("Scan");
        styleAsPrimaryAction(scanButton);
        this.statusCluster = new StatusCluster();

        endpointField.setToolTipText("MCP server URL (e.g. https://mcp.example.com/mcp)");
        transportCombo.setToolTipText("Streamable HTTP is recommended — use SSE for legacy servers");
        authTypeCombo.setToolTipText("Authentication type to use when connecting to the MCP server");
        primaryButton.setToolTipText("Connect to the configured MCP server");
        scanButton.setToolTipText("Run all enabled scan checks against the discovered inventory");

        toolTablePanel.setSelectionPersistence(configStore, this::activeEndpoint);
        toolTablePanel.setStatusReporter(eventLog::info);

        seedFromConfig();
        serverConfigPanel.showAuthCard((String) authTypeCombo.getSelectedItem());
        serverConfigPanel.setEndpointSupplier(() -> endpointField.getText().trim());

        inspectorPanel.setMinimumSize(new Dimension(0, 0));
        JTabbedPane inventoryTabs = new JTabbedPane();
        inventoryTabs.addTab("Tools", toolTablePanel);
        inventoryTabs.addTab("Resources", resourceTablePanel);
        inventoryTabs.addTab("Templates", resourceTemplateTablePanel);
        inventoryTabs.addTab("Prompts", promptTablePanel);
        inventoryTabs.addTab("Server Info", serverInfoPanel);
        inventoryTabs.setSelectedIndex(0);
        JSplitPane splitPane = new JSplitPane(
                JSplitPane.HORIZONTAL_SPLIT,
                inventoryTabs,
                inspectorPanel);
        splitPane.setResizeWeight(0.7);
        splitPane.setContinuousLayout(true);
        splitPane.setBorder(null);

        add(buildHeader(), BorderLayout.NORTH);
        add(splitPane, BorderLayout.CENTER);

        wireListeners();
        renderState();
    }

    public void shutdown() {
        scanLauncher.cancelActiveScans();
        serverConfigPanel.shutdown();
    }

    private void seedFromConfig() {
        String savedEndpoint = configStore.endpoint();
        if (savedEndpoint != null) {
            endpointField.setText(savedEndpoint);
        }
        String savedTransport = configStore.transport();
        if (savedTransport != null) {
            try {
                transportCombo.setSelectedItem(TransportType.valueOf(savedTransport));
            } catch (IllegalArgumentException ignored) {
            }
        }
        String savedAuthType = configStore.authType();
        authTypeCombo.setSelectedItem(savedAuthType != null ? savedAuthType : ServerConfigPanel.AUTH_OAUTH);
    }

    private JPanel buildHeader() {
        JPanel header = new JPanel(new BorderLayout());
        header.add(buildStatusRow(), BorderLayout.NORTH);
        header.add(buildConfigToolbar(), BorderLayout.CENTER);
        return header;
    }

    private JPanel buildStatusRow() {
        JPanel statusRow = new JPanel(new BorderLayout());
        statusCluster.setBorder(BorderFactory.createEmptyBorder(4, 12, 4, 12));
        statusRow.add(statusCluster, BorderLayout.CENTER);
        statusRow.add(buildSupportLinks(), BorderLayout.EAST);
        statusRow.setBorder(BorderFactory.createMatteBorder(0, 0, 1, 0, separatorColor()));
        return statusRow;
    }

    private JPanel buildSupportLinks() {
        JPanel rightLinks = new JPanel(new FlowLayout(FlowLayout.RIGHT, 0, 0));
        rightLinks.add(new HyperlinkLabel("Report a bug",
                URI.create("https://github.com/peter-hendy/mcp-server-scanner-extension/issues/new?labels=bug"),
                logging::logToError));
        rightLinks.add(new JLabel(" · "));
        rightLinks.add(new HyperlinkLabel("Request a feature",
                URI.create("https://github.com/peter-hendy/mcp-server-scanner-extension/issues/new?labels=enhancement"),
                logging::logToError));
        rightLinks.setBorder(BorderFactory.createEmptyBorder(4, 12, 4, 12));
        return rightLinks;
    }

    private static Color separatorColor() {
        Color color = UIManager.getColor("Separator.foreground");
        return color != null ? color : Color.GRAY.brighter();
    }

    private JPanel buildConfigToolbar() {
        endpointField.setMaximumSize(
                new Dimension(Integer.MAX_VALUE, endpointField.getPreferredSize().height));
        clampMaxHeight(transportCombo);
        clampMaxHeight(authTypeCombo);

        JPanel toolbar = new JPanel();
        toolbar.setLayout(new BoxLayout(toolbar, BoxLayout.LINE_AXIS));
        toolbar.setBorder(BorderFactory.createEmptyBorder(8, 12, 8, 12));

        toolbar.add(new JLabel("Endpoint:"));
        toolbar.add(Box.createHorizontalStrut(8));
        toolbar.add(endpointField);
        toolbar.add(Box.createHorizontalStrut(12));
        toolbar.add(new JLabel("Transport:"));
        toolbar.add(Box.createHorizontalStrut(8));
        toolbar.add(transportCombo);
        toolbar.add(Box.createHorizontalStrut(12));
        toolbar.add(new JLabel("Auth:"));
        toolbar.add(Box.createHorizontalStrut(8));
        toolbar.add(authTypeCombo);

        toolbar.add(Box.createHorizontalStrut(12));
        toolbar.add(verticalSeparator());
        toolbar.add(Box.createHorizontalStrut(12));
        toolbar.add(primaryButton);
        toolbar.add(Box.createHorizontalStrut(12));
        toolbar.add(verticalSeparator());
        toolbar.add(Box.createHorizontalStrut(12));
        toolbar.add(scanButton);

        return toolbar;
    }

    private static JButton createToolbarButton(String label) {
        JButton button = new JButton(label);
        button.setMargin(BUTTON_MARGIN);
        return button;
    }

    private static void styleAsPrimaryAction(JButton button) {
        button.setForeground(Color.WHITE);
        button.setFocusPainted(false);
        button.setBorderPainted(false);
        button.setContentAreaFilled(false);
        button.setOpaque(false);
        button.setUI(new PrimaryActionButtonUI());
    }

    private static final class PrimaryActionButtonUI extends javax.swing.plaf.basic.BasicButtonUI {
        @Override
        public void paint(java.awt.Graphics g, JComponent c) {
            AbstractButton button = (AbstractButton) c;
            java.awt.Graphics2D g2 = (java.awt.Graphics2D) g.create();
            try {
                g2.setRenderingHint(java.awt.RenderingHints.KEY_ANTIALIASING,
                        java.awt.RenderingHints.VALUE_ANTIALIAS_ON);
                g2.setColor(backgroundFor(button));
                g2.fillRoundRect(0, 0, c.getWidth(), c.getHeight(), 6, 6);
            } finally {
                g2.dispose();
            }
            super.paint(g, c);
        }

        private static Color backgroundFor(AbstractButton button) {
            if (!button.isEnabled()) {
                return PORTSWIGGER_ORANGE_DISABLED;
            }
            if (button.getModel().isPressed()) {
                return PORTSWIGGER_ORANGE_PRESSED;
            }
            if (button.getModel().isRollover()) {
                return PORTSWIGGER_ORANGE_HOVER;
            }
            return PORTSWIGGER_ORANGE;
        }
    }

    private static JSeparator verticalSeparator() {
        JSeparator separator = new JSeparator(SwingConstants.VERTICAL);
        separator.setMaximumSize(new Dimension(2, TOOLBAR_WIDGET_HEIGHT));
        return separator;
    }

    private static void clampMaxHeight(JComponent component) {
        component.setMaximumSize(
                new Dimension(component.getPreferredSize().width, component.getPreferredSize().height));
    }

    private void wireListeners() {
        authTypeCombo.addActionListener(e -> {
            serverConfigPanel.showAuthCard((String) authTypeCombo.getSelectedItem());
            configStore.setAuthType((String) authTypeCombo.getSelectedItem());
            refreshScanButtonEnabled();
        });
        endpointField.getDocument().addDocumentListener(new EndpointTextWatcher());
        transportCombo.addActionListener(e -> {
            TransportType selected = (TransportType) transportCombo.getSelectedItem();
            if (selected != null) {
                configStore.setTransport(selected.name());
            }
        });
        primaryButton.addActionListener(e -> onPrimary());
        scanButton.addActionListener(e -> onScan());
        wireSelectionListener(toolTablePanel.getTableModel());
        wireSelectionListener(resourceTablePanel.getTableModel());
        wireSelectionListener(resourceTemplateTablePanel.getTableModel());
        wireSelectionListener(promptTablePanel.getTableModel());
        clientManager.addDisconnectListener(
                () -> SwingUtilities.invokeLater(() -> dispatch(UiAction.ExternalDisconnect.INSTANCE)));
    }

    private void onPrimary() {
        if (state instanceof UiConnectionState.Connecting || state instanceof UiConnectionState.Connected) {
            dispatch(UiAction.DisconnectRequested.INSTANCE);
            return;
        }
        onConnect();
    }

    private void onConnect() {
        String endpoint = endpointField.getText().trim();
        if (endpoint.isEmpty()) {
            dispatch(new UiAction.ConnectRejected(ConnectPhase.CONNECT, "endpoint URL is required"));
            return;
        }
        if (!hasHttpScheme(endpoint)) {
            dispatch(new UiAction.ConnectRejected(ConnectPhase.CONNECT, "Endpoint must use http or https"));
            return;
        }

        String authType = (String) authTypeCombo.getSelectedItem();
        TransportType transport = (TransportType) transportCombo.getSelectedItem();

        OAuthClientHints hints = null;
        URI mcpResource = null;
        AuthStrategy snapshotAuth = null;
        if (ServerConfigPanel.AUTH_OAUTH.equals(authType)) {
            try {
                hints = serverConfigPanel.buildOauthHintsSnapshot();
                mcpResource = URI.create(endpoint);
            } catch (IllegalArgumentException ex) {
                dispatch(new UiAction.ConnectRejected(ConnectPhase.OAUTH, ex.getMessage()));
                return;
            }
        } else {
            try {
                snapshotAuth = serverConfigPanel.currentAuthStrategy();
            } catch (IllegalArgumentException ex) {
                dispatch(new UiAction.ConnectRejected(ConnectPhase.CONNECT, ex.getMessage()));
                return;
            }
        }

        String host = extractHost(endpoint);
        ConnectAttempt attempt = ServerConfigPanel.AUTH_OAUTH.equals(authType)
                ? ConnectAttempt.withOauth(endpoint, transport, host, authType, hints, mcpResource)
                : ConnectAttempt.withSnapshot(endpoint, transport, host, authType, snapshotAuth);
        dispatch(new UiAction.ConnectRequested(attempt));
    }

    private static void requireEdt() {
        if (!SwingUtilities.isEventDispatchThread()) {
            throw new IllegalStateException("Must be called on the Event Dispatch Thread");
        }
    }

    private void dispatch(UiAction action) {
        requireEdt();
        UiStateReducer.Reduction reduction = reducer.reduce(state, action);
        this.state = reduction.state();
        for (UiSideEffect effect : reduction.sideEffects()) {
            apply(effect);
        }
        renderState();
    }

    private void apply(UiSideEffect effect) {
        if (effect instanceof UiSideEffect.SpawnConnectWorker spawn) {
            spawnConnectWorker(spawn.attempt());
        } else if (effect instanceof UiSideEffect.CancelConnect cancel) {
            cancel.cancellable().cancel();
        } else if (effect instanceof UiSideEffect.RunDisconnect) {
            spawnDisconnectWorker();
        } else if (effect instanceof UiSideEffect.PublishOAuthStrategy publish) {
            serverConfigPanel.publishOauthStrategy(publish.strategy());
        } else if (effect instanceof UiSideEffect.ClearOAuthStrategy) {
            serverConfigPanel.clearOauthStrategy();
        } else if (effect instanceof UiSideEffect.ClearAutoDiscoveredOAuthFields) {
            serverConfigPanel.clearAutoDiscoveredOAuth();
        } else if (effect instanceof UiSideEffect.PopulateInventory populate) {
            populateInventoryPanels(populate.result());
        } else if (effect instanceof UiSideEffect.ClearInventory) {
            clearInventoryPanels();
        } else if (effect instanceof UiSideEffect.LogWarning warning) {
            eventLog.warn(warning.message());
        }
    }

    private void spawnConnectWorker(ConnectAttempt attempt) {
        SwingWorker<ConnectionAttemptResult, UiAction.ConnectProgress> worker = new SwingWorker<>() {
            @Override
            protected ConnectionAttemptResult doInBackground() {
                return connectCoordinator.connect(
                        attempt,
                        (phase, message) -> publish(new UiAction.ConnectProgress(phase, message)),
                        McpScannerTab.this::onAuthTerminallyFailed);
            }

            @Override
            protected void process(List<UiAction.ConnectProgress> chunks) {
                dispatch(chunks.get(chunks.size() - 1));
            }

            @Override
            protected void done() {
                if (isCancelled()) {
                    return;
                }
                try {
                    ConnectionAttemptResult outcome = get();
                    ConnectResult result = outcome.result();
                    ConnectionStatus connectedStatus = serverConfigPanel.buildConnectedStatus(
                            attempt.host(), result.tools().size());
                    dispatch(new UiAction.ConnectSucceeded(
                            result, attempt.host(), connectedStatus, outcome.oauthStrategy()));
                } catch (Exception ex) {
                    String reason = extractReason(ex);
                    logging.logToError("Connection failed: " + reason);
                    dispatch(new UiAction.ConnectFailed(reason));
                }
            }
        };
        Cancellable cancellable = () -> {
            if (!worker.isDone()) {
                worker.cancel(true);
            }
            CallbackListener.closeAll();
        };
        dispatch(new UiAction.ConnectWorkerAttached(cancellable));
        worker.execute();
    }

    private void spawnDisconnectWorker() {
        new SwingWorker<Void, Void>() {
            @Override
            protected Void doInBackground() {
                clientManager.disconnect();
                return null;
            }

            @Override
            protected void done() {
                try {
                    get();
                } catch (Exception ex) {
                    logging.logToError("Disconnect failed: " + extractReason(ex));
                }
            }
        }.execute();
    }

    private void populateInventoryPanels(ConnectResult result) {
        toolTablePanel.populate(result.tools());
        resourceTablePanel.populate(result.resources());
        resourceTemplateTablePanel.populate(result.resourceTemplates());
        promptTablePanel.populate(result.prompts());
        serverInfoPanel.populate(result.serverMetadata());
    }

    private void clearInventoryPanels() {
        toolTablePanel.populate(List.of());
        resourceTablePanel.populate(List.of());
        resourceTemplateTablePanel.populate(List.of());
        promptTablePanel.populate(List.of());
        serverInfoPanel.populate(ServerMetadata.empty());
    }

    private void renderState() {
        ConnectionStatus status = state.status();
        statusCluster.update(status);
        primaryButton.setText(status.primaryButtonLabel());
        primaryButton.setToolTipText(primaryButtonTooltip(status.primaryButtonLabel()));
        applyConfigurationLock(state instanceof UiConnectionState.Connected);
        refreshScanButtonEnabled();
    }

    private static String primaryButtonTooltip(String label) {
        return "Disconnect".equals(label)
                ? "Disconnect from the MCP server"
                : "Connect to the configured MCP server";
    }

    private void applyConfigurationLock(boolean locked) {
        endpointField.setEnabled(!locked);
        transportCombo.setEnabled(!locked);
        authTypeCombo.setEnabled(!locked);
        serverConfigPanel.setConfigurationLocked(locked);
        if (!locked) {
            serverConfigPanel.revalidate();
            serverConfigPanel.repaint();
        }
    }

    private void refreshScanButtonEnabled() {
        scanButton.setEnabled(state instanceof UiConnectionState.Connected
                && clientManager.isConnected()
                && hasAnySelection());
    }

    private boolean hasAnySelection() {
        return !toolTablePanel.selectedTools().isEmpty()
                || !resourceTablePanel.selectedResources().isEmpty()
                || !resourceTemplateTablePanel.selectedResourceTemplates().isEmpty()
                || !promptTablePanel.selectedPrompts().isEmpty();
    }

    private void wireSelectionListener(InventoryTableModel<?> model) {
        model.addTableModelListener(e -> {
            if (e.getType() != TableModelEvent.UPDATE || e.getColumn() == 0) {
                refreshScanButtonEnabled();
            }
        });
    }

    private void onScan() {
        List<McpToolDefinition> selectedTools = toolTablePanel.selectedTools();
        if (!hasAnySelection()) {
            logging.logToError("Scan skipped: no items selected");
            return;
        }

        AuthStrategy strategy = resolveAuthStrategy();
        authHolder.set(strategy);
        Map<String, String> sessionHeaders = clientManager.scannerSession().scannerHeaders();
        String endpoint = clientManager.scannerSession().resolvedEndpoint();

        if (!confirmDestructiveScan(selectedTools, endpoint)) {
            return;
        }

        ScanInventory inventory = selectedInventory(selectedTools);
        selectionHolder.set(inventory);

        eventLog.info(scanStartedMessage(selectedTools.size()));
        flashScanButtonLaunched();

        new SwingWorker<Void, Void>() {
            @Override
            protected Void doInBackground() {
                Map<String, String> headers = new HashMap<>(sessionHeaders);
                headers.putAll(strategy.headers());
                scanLauncher.launchScan(endpoint, inventory, headers);
                return null;
            }

            @Override
            protected void done() {
                // overlayStatus is a deliberate side-channel for ephemeral toast notifications; only connection-lifecycle state flows through the reducer.
                try {
                    get();
                    logging.logToOutput("Scan launched for " + inventory.totalCount() + " MCP entities");
                    overlayStatus(ConnectionStatus.scanLaunched(selectedTools.size()));
                } catch (Exception ex) {
                    String reason = extractReason(ex);
                    logging.logToError("Scan failed: " + reason);
                    overlayStatus(ConnectionStatus.scanFailed(reason));
                }
            }
        }.execute();
    }

    private void flashScanButtonLaunched() {
        String originalText = scanButton.getText();
        scanButton.setEnabled(false);
        scanButton.setText("Scan launched ✓");
        Timer revert = new Timer(SCAN_LAUNCHED_FLASH_MS, e -> {
            scanButton.setText(originalText);
            refreshScanButtonEnabled();
        });
        revert.setRepeats(false);
        revert.start();
    }

    private String scanStartedMessage(int selectedToolCount) {
        long activeMcpCheckCount = checkRegistry.enabledActiveCheckCount();
        return "Scan started — " + selectedToolCount + " tool(s), "
                + activeMcpCheckCount + " MCP checks, + Burp built-in checks.";
    }

    private boolean confirmDestructiveScan(List<McpToolDefinition> selectedTools, String endpoint) {
        if (endpoint == null || endpoint.isEmpty()) {
            logging.logToError("Scan blocked: no resolved endpoint to scope destructive-scan confirmation against");
            return false;
        }
        if (!DestructiveScanConfirmation.requiresConfirmation(
                selectedTools, configStore.dontAskAgain(endpoint))) {
            return true;
        }
        List<McpToolDefinition> nonReadOnly = DestructiveScanConfirmation.nonReadOnly(selectedTools);
        DestructiveScanConfirmation.Result result = confirmationPrompt.apply(nonReadOnly);
        if (!result.proceed()) {
            return false;
        }
        if (result.dontAskAgain()) {
            configStore.setDontAskAgain(endpoint, true);
        }
        return true;
    }

    private String activeEndpoint() {
        return clientManager.isConnected()
                ? clientManager.scannerSession().resolvedEndpoint()
                : null;
    }

    private ScanInventory selectedInventory(List<McpToolDefinition> selectedTools) {
        return new ScanInventory(
                selectedTools,
                resourceTablePanel.selectedResources(),
                resourceTemplateTablePanel.selectedResourceTemplates(),
                promptTablePanel.selectedPrompts());
    }

    private void overlayStatus(ConnectionStatus status) {
        statusCluster.update(status);
        primaryButton.setText(status.primaryButtonLabel());
        primaryButton.setToolTipText(primaryButtonTooltip(status.primaryButtonLabel()));
    }

    private void onAuthTerminallyFailed() {
        SwingUtilities.invokeLater(() -> {
            scanLauncher.cancelActiveScans();
            overlayStatus(ConnectionStatus.authTerminallyFailed());
        });
    }

    private AuthStrategy resolveAuthStrategy() {
        return authStrategyOverride != null ? authStrategyOverride : serverConfigPanel.currentAuthStrategy();
    }

    private String extractReason(Exception ex) {
        Throwable cause = ex;
        while (cause.getCause() != null && cause.getCause() != cause) {
            cause = cause.getCause();
        }
        return cause.getMessage() != null ? cause.getMessage() : cause.getClass().getSimpleName();
    }

    private static boolean hasHttpScheme(String url) {
        try {
            String scheme = URI.create(url).getScheme();
            return "http".equalsIgnoreCase(scheme) || "https".equalsIgnoreCase(scheme);
        } catch (IllegalArgumentException e) {
            return false;
        }
    }

    private String extractHost(String url) {
        try {
            URI uri = URI.create(url);
            String host = uri.getHost();
            return host != null ? host : url;
        } catch (IllegalArgumentException e) {
            return url;
        }
    }

    JTextField endpointFieldForTest() {
        return endpointField;
    }

    JComboBox<TransportType> transportComboForTest() {
        return transportCombo;
    }

    JComboBox<String> authTypeComboForTest() {
        return authTypeCombo;
    }

    JButton primaryButtonForTest() {
        return primaryButton;
    }

    JButton scanButtonForTest() {
        return scanButton;
    }

    StatusCluster statusClusterForTest() {
        return statusCluster;
    }

    InspectorPanel inspectorPanelForTest() {
        return inspectorPanel;
    }

    ServerConfigPanel serverConfigPanelForTest() {
        return serverConfigPanel;
    }

    void setAuthStrategyOverrideForTest(AuthStrategy override) {
        this.authStrategyOverride = override;
    }

    void setConfirmationPromptForTest(
            Function<List<McpToolDefinition>, DestructiveScanConfirmation.Result> prompt) {
        this.confirmationPrompt = prompt;
    }

    void populateToolsForTest(List<McpToolDefinition> tools) {
        toolTablePanel.populate(tools);
    }

    void populateAllInventoriesForTest(ConnectResult result) {
        populateInventoryPanels(result);
    }

    ToolTablePanel toolTablePanelForTest() {
        return toolTablePanel;
    }

    ResourceTablePanel resourceTablePanelForTest() {
        return resourceTablePanel;
    }

    ResourceTemplateTablePanel resourceTemplateTablePanelForTest() {
        return resourceTemplateTablePanel;
    }

    PromptTablePanel promptTablePanelForTest() {
        return promptTablePanel;
    }

    ServerInfoPanel serverInfoPanelForTest() {
        return serverInfoPanel;
    }

    void setStateForTest(UiConnectionState newState) {
        this.state = newState;
        renderState();
    }

    UiConnectionState stateForTest() {
        return state;
    }

    private final class EndpointTextWatcher implements DocumentListener {

        private String previousHost = parseHostOrEmpty(endpointField.getText().trim());

        @Override
        public void insertUpdate(DocumentEvent e) {
            onChange();
        }

        @Override
        public void removeUpdate(DocumentEvent e) {
            onChange();
        }

        @Override
        public void changedUpdate(DocumentEvent e) {
            onChange();
        }

        private void onChange() {
            String endpoint = endpointField.getText().trim();
            configStore.setEndpoint(endpoint);
            String currentHost = parseHostOrEmpty(endpoint);
            if (!currentHost.equals(previousHost)) {
                previousHost = currentHost;
                serverConfigPanel.clearAutoDiscoveredOAuth();
            }
            serverConfigPanel.onEndpointChanged();
            refreshScanButtonEnabled();
        }
    }

    private static String parseHostOrEmpty(String endpoint) {
        if (endpoint == null || endpoint.isEmpty()) {
            return "";
        }
        try {
            String host = URI.create(endpoint).getHost();
            return host != null ? host : "";
        } catch (IllegalArgumentException e) {
            return "";
        }
    }
}
