package com.mcpscanner.automation;

import com.mcpscanner.scan.ScanInventory;

import java.util.ArrayList;
import java.util.List;

public record CatalogLimit(int perKind) {

    public static final CatalogLimit NONE = new CatalogLimit(Integer.MAX_VALUE);

    public CatalogLimit {
        if (perKind < 1) {
            throw new IllegalArgumentException("a catalog limit must keep at least 1 item per kind, got " + perKind);
        }
    }

    public static CatalogLimit of(Integer perKind) {
        return perKind == null ? NONE : new CatalogLimit(perKind);
    }

    public LimitedInventory applyTo(ScanInventory inventory) {
        List<String> trimmed = new ArrayList<>();
        ScanInventory limited = new ScanInventory(
                keep("tools", inventory.tools(), trimmed),
                keep("resources", inventory.resources(), trimmed),
                keep("resource templates", inventory.resourceTemplates(), trimmed),
                keep("prompts", inventory.prompts(), trimmed));
        return new LimitedInventory(limited, perKind, trimmed);
    }

    private <T> List<T> keep(String kind, List<T> items, List<String> trimmed) {
        if (items.size() <= perKind) {
            return items;
        }
        trimmed.add(kind + " " + items.size() + " -> " + perKind);
        return items.subList(0, perKind);
    }
}
