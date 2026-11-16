package com.mcpscanner.cvetargets.mining;

import com.mcpscanner.access.mining.AccessMining;
import com.mcpscanner.access.mining.MiningInputs;
import com.mcpscanner.access.mining.MiningListener;
import com.mcpscanner.access.mining.MiningPreferences;
import com.mcpscanner.access.mining.MiningReport;
import com.mcpscanner.access.mining.MiningSender;
import com.mcpscanner.access.mining.MiningStep;
import com.mcpscanner.access.mining.WriteCallApproval;
import com.mcpscanner.auth.AuthStrategy;
import com.mcpscanner.checks.api.Principal;
import com.mcpscanner.checks.api.PrincipalRoster;
import com.mcpscanner.config.ExtensionConfigStore;
import com.mcpscanner.identity.Identity;
import com.mcpscanner.identity.IdentityAuthKind;
import com.mcpscanner.identity.IdentityOAuthSettings;
import com.mcpscanner.identity.IdentityRegistry;
import com.mcpscanner.identity.IdentityRole;
import com.mcpscanner.identity.IdentityRosterSource;
import com.mcpscanner.identity.IdentityStore;
import com.mcpscanner.identity.OwnedValueStore;
import com.mcpscanner.identity.OwnedValues;
import com.mcpscanner.identity.RegistryOwnedValues;
import com.mcpscanner.logging.McpEventLog;
import com.mcpscanner.scan.ScanInventory;
import com.mcpscanner.testutil.ScratchConfig;

import java.util.List;
import java.util.Optional;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.function.Supplier;

public final class ArmUsers {

    private final IdentityRegistry registry;
    private final ExtensionConfigStore config;
    private final Supplier<PrincipalRoster> roster;
    private final OwnedValueStore ownedValues;

    private ArmUsers(IdentityRegistry registry, ExtensionConfigStore config, Supplier<AuthStrategy> connectionAuth) {
        this.registry = registry;
        this.config = config;
        this.roster = new IdentityRosterSource(connectionAuth, registry);
        this.ownedValues = new RegistryOwnedValues(registry);
    }

    public static ArmUsers of(Supplier<PrincipalRoster> declared, Supplier<AuthStrategy> connectionAuth) {
        ExtensionConfigStore config = ScratchConfig.store();
        IdentityRegistry registry = new IdentityRegistry(new IdentityStore(config, McpEventLog.noop()));
        PrincipalRoster arm = declared.get();
        registry.update(described(registry.primaryUser(), arm.primary()));
        arm.compared().forEach(principal -> addCompared(registry, principal));
        return new ArmUsers(registry, config, connectionAuth);
    }

    public Supplier<PrincipalRoster> roster() {
        return roster;
    }

    public OwnedValueStore ownedValues() {
        return ownedValues;
    }

    public MiningReport mine(ScanInventory inventory, MiningSender sender) {
        ExecutorService worker = Executors.newSingleThreadExecutor();
        try {
            CompletableFuture<MiningReport> finished = new CompletableFuture<>();
            new AccessMining(new MiningInputs(() -> Optional.of(inventory), roster,
                    () -> registry.primaryUser().id()), sender, new MiningPreferences(config), ownedValues, worker,
                    () -> Runnable::run, McpEventLog.noop())
                    .start(finishing(finished), WriteCallApproval.REFUSE)
                    .orElseThrow(() -> new IllegalStateException("mining did not start"));
            return finished.join();
        } finally {
            worker.shutdownNow();
        }
    }

    private static void addCompared(IdentityRegistry registry, Principal principal) {
        Identity added = registry.add(new Identity(principal.id(), principal.name(), roleOf(principal),
                IdentityAuthKind.CUSTOM_HEADERS, true, principal.privateMarker(),
                OwnedValues.entered(principal.ownedObjects().all()), IdentityOAuthSettings.none(), List.of()));
        registry.setCredential(added.id(), () -> principal.credentialHeaders().get());
    }

    private static Identity described(Identity connectAs, Principal primary) {
        return connectAs.withName(primary.name()).withPrivateMarker(primary.privateMarker().orElse(null))
                .withOwnedValues(OwnedValues.entered(primary.ownedObjects().all()));
    }

    private static IdentityRole roleOf(Principal principal) {
        return switch (principal.role()) {
            case LOWER -> IdentityRole.LOWER;
            case HIGHER -> IdentityRole.HIGHER;
            case PEER, PRIMARY -> IdentityRole.PEER;
        };
    }

    private static MiningListener finishing(CompletableFuture<MiningReport> finished) {
        return new MiningListener() {
            @Override
            public void progressed(String user, MiningStep step) {
            }

            @Override
            public void finished(MiningReport report) {
                finished.complete(report);
            }
        };
    }
}
