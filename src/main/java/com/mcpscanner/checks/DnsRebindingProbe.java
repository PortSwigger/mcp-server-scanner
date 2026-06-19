package com.mcpscanner.checks;

import java.util.List;
import java.util.Map;

public record DnsRebindingProbe(String id,
                                String displayName,
                                Category category,
                                List<String> headersToRemove,
                                Map<String, String> headersToOverride) {

    public enum Category {
        HOST_OVERRIDE,
        ORIGIN_OVERRIDE
    }

    public DnsRebindingProbe {
        headersToRemove = List.copyOf(headersToRemove);
        headersToOverride = Map.copyOf(headersToOverride);
    }

    public static final List<DnsRebindingProbe> PROBES = List.of(
            new DnsRebindingProbe(
                    "HOSTILE_ORIGIN",
                    "Origin: http://evil.example",
                    Category.ORIGIN_OVERRIDE,
                    List.of(),
                    Map.of("Origin", "http://evil.example")),
            new DnsRebindingProbe(
                    "NULL_ORIGIN",
                    "Origin: null",
                    Category.ORIGIN_OVERRIDE,
                    List.of(),
                    Map.of("Origin", "null")),
            new DnsRebindingProbe(
                    "ATTACKER_DOMAIN_ORIGIN",
                    "Origin: http://attacker.example:1337",
                    Category.ORIGIN_OVERRIDE,
                    List.of(),
                    Map.of("Origin", "http://attacker.example:1337")),
            new DnsRebindingProbe(
                    "HOSTILE_HOST",
                    "Host: attacker.example + Origin: http://attacker.example",
                    Category.HOST_OVERRIDE,
                    List.of(),
                    Map.of("Host", "attacker.example",
                           "Origin", "http://attacker.example"))
    );
}
