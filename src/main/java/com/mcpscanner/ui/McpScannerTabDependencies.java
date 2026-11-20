package com.mcpscanner.ui;

import com.mcpscanner.ui.widgets.DialogOwner;
import burp.api.montoya.logging.Logging;
import com.mcpscanner.auth.AuthStrategy;
import com.mcpscanner.auth.CurrentAuthHolder;
import com.mcpscanner.auth.grants.OptionalGrantSettings;
import com.mcpscanner.client.McpClientManager;
import com.mcpscanner.config.ExtensionConfigStore;
import com.mcpscanner.logging.McpEventLog;
import com.mcpscanner.scan.ScanConnection;
import com.mcpscanner.scan.request.ScanMessageRenderer;
import com.mcpscanner.ui.identities.UsersMode;
import com.mcpscanner.ui.widgets.UiReads;

import java.net.URI;
import java.util.Objects;
import java.util.Optional;
import java.util.function.BiFunction;
import java.util.function.Supplier;

public record McpScannerTabDependencies(McpClientManager clientManager,
                                        Logging logging,
                                        ExtensionConfigStore configStore,
                                        McpEventLog eventLog,
                                        CurrentAuthHolder authHolder,
                                        ScanMessageRenderer requestRenderer,
                                        ServerConfigPanel serverConfigPanel,
                                        Supplier<ScanConnection> repeaterConnections,
                                        BiFunction<URI, OptionalGrantSettings, AuthStrategy> optionalGrants,
                                        BurpNetworkingPrompt burpNetworkingPrompt,
                                        IdentityDependencies identities,
                                        UiReads uiReads,
                                        DialogOwner dialogOwner,
                                        Optional<ScanServices> scanServices) {

    public McpScannerTabDependencies {
        Objects.requireNonNull(authHolder, "authHolder must not be null");
        Objects.requireNonNull(requestRenderer, "requestRenderer must not be null");
        Objects.requireNonNull(serverConfigPanel, "serverConfigPanel must not be null");
        Objects.requireNonNull(optionalGrants, "optionalGrants must not be null");
        Objects.requireNonNull(burpNetworkingPrompt, "burpNetworkingPrompt must not be null");
        Objects.requireNonNull(identities, "identities must not be null");
        Objects.requireNonNull(uiReads, "uiReads must not be null");
        Objects.requireNonNull(dialogOwner, "dialogOwner must not be null");
        Objects.requireNonNull(scanServices, "scanServices must not be null");
    }

    public SettingsScope settingsScope() {
        return scanServices.isPresent() ? SettingsScope.WITH_SCANNING : SettingsScope.WITHOUT_SCANNING;
    }

    UsersMode usersMode() {
        return scanServices.isPresent() ? UsersMode.PRIMARY_AND_COMPARED : UsersMode.PRIMARY_ONLY;
    }

    InventoryTicks inventoryTicks() {
        return scanServices.isPresent() ? InventoryTicks.SCAN_SELECTION : InventoryTicks.NONE;
    }
}
