package com.mcpscanner.ui;

import com.mcpscanner.ui.widgets.DialogOwner;
import burp.api.montoya.logging.Logging;
import com.mcpscanner.scan.OwnerArgumentSource;
import com.mcpscanner.auth.AuthStrategy;
import com.mcpscanner.auth.CurrentAuthHolder;
import com.mcpscanner.auth.grants.OptionalGrantSettings;
import com.mcpscanner.checks.registry.ScanCheckRegistry;
import com.mcpscanner.checks.registry.ScanCheckSettings;
import com.mcpscanner.client.McpClientManager;
import com.mcpscanner.config.ExtensionConfigStore;
import com.mcpscanner.logging.McpEventLog;
import com.mcpscanner.scan.McpScanLauncher;
import com.mcpscanner.scan.ScanConnection;
import com.mcpscanner.scan.ScanGenerationSettings;
import com.mcpscanner.scan.ScanModeSetting;
import com.mcpscanner.scan.request.ScanMessageRenderer;
import com.mcpscanner.ui.widgets.UiReads;

import java.net.URI;
import java.util.Map;
import java.util.Objects;
import java.util.function.BiFunction;
import java.util.function.Supplier;

public record McpScannerTabDependencies(McpClientManager clientManager,
                                        McpScanLauncher scanLauncher,
                                        Logging logging,
                                        ExtensionConfigStore configStore,
                                        ScanCheckRegistry checkRegistry,
                                        ScanCheckSettings checkSettings,
                                        McpEventLog eventLog,
                                        CurrentAuthHolder authHolder,
                                        ScanGenerationSettings generationSettings,
                                        ScanModeSetting scanModeSetting,
                                        ScanMessageRenderer requestRenderer,
                                        ServerConfigPanel serverConfigPanel,
                                        Supplier<ScanConnection> repeaterConnections,
                                        BiFunction<URI, OptionalGrantSettings, AuthStrategy> optionalGrants,
                                        DestructiveScanPrompt destructiveScanPrompt,
                                        BurpNetworkingPrompt burpNetworkingPrompt,
                                        IdentityDependencies identities,
                                        OwnerArgumentSource scanOwnerArguments,
                                        UiReads uiReads,
                                        DialogOwner dialogOwner) {

    public McpScannerTabDependencies {
        Objects.requireNonNull(authHolder, "authHolder must not be null");
        Objects.requireNonNull(generationSettings, "generationSettings must not be null");
        Objects.requireNonNull(scanModeSetting, "scanModeSetting must not be null");
        Objects.requireNonNull(requestRenderer, "requestRenderer must not be null");
        Objects.requireNonNull(serverConfigPanel, "serverConfigPanel must not be null");
        Objects.requireNonNull(optionalGrants, "optionalGrants must not be null");
        Objects.requireNonNull(destructiveScanPrompt, "destructiveScanPrompt must not be null");
        Objects.requireNonNull(burpNetworkingPrompt, "burpNetworkingPrompt must not be null");
        Objects.requireNonNull(identities, "identities must not be null");
        Objects.requireNonNull(scanOwnerArguments, "scanOwnerArguments must not be null");
        Objects.requireNonNull(uiReads, "uiReads must not be null");
        Objects.requireNonNull(dialogOwner, "dialogOwner must not be null");
    }
}
