package com.mcpscanner.config;

import java.util.Arrays;
import java.util.List;

public enum ResourceCap {
    PROXY_POST_BODY_BYTES(SettingKey.CAP_PROXY_POST_BODY, "Maximum proxy POST body",
            32L * 1024 * 1024, Integer.MAX_VALUE - 1L, CapUnit.BYTES, CapKind.SAFETY_LIMIT),
    SSE_PENDING_RESPONSE_BYTES(SettingKey.CAP_SSE_PENDING_RESPONSE, "Unclaimed SSE response buffer",
            64L * 1024 * 1024, Long.MAX_VALUE, CapUnit.BYTES, CapKind.SAFETY_LIMIT),
    DISCOVERY_TOTAL_BYTES(SettingKey.CAP_DISCOVERY_TOTAL, "Discovery data per list",
            256L * 1024 * 1024, Long.MAX_VALUE, CapUnit.BYTES, CapKind.SAFETY_LIMIT),
    DISCOVERY_MAX_PAGES(SettingKey.CAP_DISCOVERY_MAX_PAGES, "Discovery pages per list",
            100, Integer.MAX_VALUE, CapUnit.COUNT, CapKind.SAFETY_LIMIT),
    MINING_REQUESTS_PER_USER(SettingKey.CAP_MINING_REQUESTS_PER_USER, "Collect IDs requests per user",
            0, 0, Integer.MAX_VALUE, CapUnit.COUNT, CapKind.SAFETY_LIMIT),
    EXTENSION_SCAN_WORKERS(SettingKey.CAP_EXTENSION_SCAN_WORKERS, "Extension scan workers", 10, 50, CapUnit.COUNT,
            CapKind.SCAN_THROUGHPUT);

    private static final long LOWEST_POSITIVE = 1;

    private final SettingKey key;
    private final String label;
    private final long defaultValue;
    private final long minValue;
    private final long maxValue;
    private final CapUnit unit;
    private final CapKind kind;

    ResourceCap(SettingKey key, String label, long defaultValue, long maxValue, CapUnit unit, CapKind kind) {
        this(key, label, defaultValue, LOWEST_POSITIVE, maxValue, unit, kind);
    }

    ResourceCap(SettingKey key, String label, long defaultValue, long minValue, long maxValue, CapUnit unit,
                CapKind kind) {
        this.key = key;
        this.label = label;
        this.defaultValue = defaultValue;
        this.minValue = minValue;
        this.maxValue = maxValue;
        this.unit = unit;
        this.kind = kind;
    }

    public static List<ResourceCap> ofKind(CapKind kind) {
        return Arrays.stream(values()).filter(cap -> cap.kind == kind).toList();
    }

    public CapKind kind() {
        return kind;
    }

    public CapUnit unit() {
        return unit;
    }

    public String key() {
        return key.key();
    }

    public String label() {
        return label;
    }

    public long defaultValue() {
        return defaultValue;
    }

    public long minValue() {
        return minValue;
    }

    public long maxValue() {
        return maxValue;
    }

    public boolean accepts(long value) {
        return value >= minValue && value <= maxValue;
    }
}
