package com.mcpscanner.ui;

import java.util.Optional;
import java.util.function.Supplier;

enum InventoryTicks {
    SCAN_SELECTION,
    NONE;

    boolean shown() {
        return this == SCAN_SELECTION;
    }

    <P> Optional<P> ifScanning(Supplier<P> part) {
        return this == SCAN_SELECTION ? Optional.of(part.get()) : Optional.empty();
    }
}
