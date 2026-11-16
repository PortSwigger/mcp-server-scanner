package com.mcpscanner.automation;

import com.mcpscanner.client.TransportType;

import java.util.List;
import java.util.Objects;
import java.util.Set;

public record ScanAllCommand(String endpoint, TransportType transport, CommandAuth auth, Set<String> checks,
                             List<SeedCall> seeds, Boolean useBurpNetworking,
                             boolean divertBuiltInChecks, CommandIdentities identities, Integer maxCatalogItems)
        implements ConnectCommand {

    public static final String EVERY_CHECK = "*";

    public ScanAllCommand {
        Objects.requireNonNull(endpoint, "endpoint");
        transport = transport == null ? TransportType.AUTO : transport;
        auth = auth == null ? CommandAuth.NONE : auth;
        checks = checks == null ? Set.of() : Set.copyOf(checks);
        seeds = seeds == null ? List.of() : List.copyOf(seeds);
        identities = identities == null ? CommandIdentities.NONE : identities;
    }

    public ScanAllCommand(String endpoint, TransportType transport, CommandAuth auth, Set<String> checks,
                          List<SeedCall> seeds, Boolean useBurpNetworking, boolean divertBuiltInChecks,
                          CommandIdentities identities) {
        this(endpoint, transport, auth, checks, seeds, useBurpNetworking, divertBuiltInChecks, identities, null);
    }

    CatalogLimit catalogLimit() {
        return CatalogLimit.of(maxCatalogItems);
    }

    boolean enables(String checkId) {
        return checks.contains(EVERY_CHECK) || checks.contains(checkId);
    }
}
