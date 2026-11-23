package com.mcpscanner.ui;

import com.mcpscanner.checks.registry.ScanCheckRegistry;
import com.mcpscanner.checks.registry.ScanCheckSettings;
import com.mcpscanner.config.SignedInConsentSetting;
import com.mcpscanner.scan.McpScanLauncher;
import com.mcpscanner.scan.OwnerArgumentSource;
import com.mcpscanner.scan.ScanGenerationSettings;
import com.mcpscanner.scan.ScanModeSetting;

import java.util.Objects;

public record ScanServices(McpScanLauncher scanLauncher,
                           ScanCheckRegistry checkRegistry,
                           ScanCheckSettings checkSettings,
                           ScanGenerationSettings generationSettings,
                           ScanModeSetting scanModeSetting,
                           DestructiveScanPrompt destructiveScanPrompt,
                           OwnerArgumentSource scanOwnerArguments,
                           SignedInConsentSetting signedInConsent) {

    public ScanServices {
        Objects.requireNonNull(scanLauncher, "scanLauncher must not be null");
        Objects.requireNonNull(checkRegistry, "checkRegistry must not be null");
        Objects.requireNonNull(checkSettings, "checkSettings must not be null");
        Objects.requireNonNull(generationSettings, "generationSettings must not be null");
        Objects.requireNonNull(scanModeSetting, "scanModeSetting must not be null");
        Objects.requireNonNull(destructiveScanPrompt, "destructiveScanPrompt must not be null");
        Objects.requireNonNull(scanOwnerArguments, "scanOwnerArguments must not be null");
        Objects.requireNonNull(signedInConsent, "signedInConsent must not be null");
    }
}
