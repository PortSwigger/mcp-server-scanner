package com.mcpscanner.scan;

import java.util.Objects;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.Supplier;

/**
 * Mutable, thread-safe holder for the {@link ScanInventory} the user selected
 * before launching a scan. Defaults to an empty inventory before any scan is
 * launched. The UI publishes the selected inventory here before invoking
 * {@link McpScanLauncher} so PER_HOST active checks can filter their discovered
 * tool/resource set against the user's selection and honour the
 * destructive-scan confirmation.
 */
public final class CurrentSelectionHolder implements Supplier<ScanInventory> {

    private final AtomicReference<ScanInventory> current = new AtomicReference<>(ScanInventory.empty());

    @Override
    public ScanInventory get() {
        return current.get();
    }

    public void set(ScanInventory inventory) {
        current.set(Objects.requireNonNull(inventory, "inventory must not be null"));
    }

    public void clear() {
        current.set(ScanInventory.empty());
    }
}
