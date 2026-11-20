package com.mcpscanner.ui;

import com.mcpscanner.config.ResourceCap;

import java.util.EnumSet;
import java.util.Set;

public enum SettingsScope {
    WITH_SCANNING,
    WITHOUT_SCANNING;

    private static final Set<ResourceCap> SCANNING_CAPS = EnumSet.of(ResourceCap.MINING_REQUESTS_PER_USER,
            ResourceCap.EXTENSION_SCAN_WORKERS);

    boolean includesScanning() {
        return this == WITH_SCANNING;
    }

    boolean shows(ResourceCap cap) {
        return includesScanning() || !SCANNING_CAPS.contains(cap);
    }
}
