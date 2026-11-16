package com.mcpscanner.automation;

import com.mcpscanner.scan.ScanInventory;

import java.util.List;
import java.util.Optional;

public record LimitedInventory(ScanInventory inventory, int perKind, List<String> trimmedKinds) {

    public LimitedInventory {
        trimmedKinds = List.copyOf(trimmedKinds);
    }

    public Optional<String> notice() {
        if (trimmedKinds.isEmpty()) {
            return Optional.empty();
        }
        return Optional.of("catalog limited to " + perKind + " items per kind (" + String.join(", ", trimmedKinds)
                + "); seed requests are still sent");
    }
}
