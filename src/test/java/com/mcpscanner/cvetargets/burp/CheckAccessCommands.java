package com.mcpscanner.cvetargets.burp;

import com.mcpscanner.automation.CheckAccessCommand;
import com.mcpscanner.cvetargets.manifest.AccessItem;
import com.mcpscanner.cvetargets.requests.ArmEndpoint;
import com.mcpscanner.cvetargets.run.ArmBoundAuth;
import com.mcpscanner.cvetargets.run.ArmRun;

import java.util.Optional;

final class CheckAccessCommands {

    private static final String OAUTH_NOT_HANDED_OVER =
            "Burp mode hands a harness-obtained OAuth session only to Scan all, not to Check access";
    private static final String ITEM_OWNED_BY_ANOTHER_IDENTITY =
            "Burp mode cannot make another identity an item's owner yet";

    private final boolean useBurpNetworking;

    CheckAccessCommands(boolean useBurpNetworking) {
        this.useBurpNetworking = useBurpNetworking;
    }

    Optional<String> notRunnable(ArmRun run) {
        boolean routedItem = run.target().manifest().identities().items().stream().map(AccessItem::seed)
                .anyMatch(seed -> seed != null && seed.sentAsIdentity());
        return credentialNotHandedOver(run)
                .or(() -> routedItem ? Optional.of(ITEM_OWNED_BY_ANOTHER_IDENTITY) : Optional.empty());
    }

    private static Optional<String> credentialNotHandedOver(ArmRun run) {
        return run.auth() instanceof ArmBoundAuth ? Optional.of(OAUTH_NOT_HANDED_OVER) : Optional.empty();
    }

    CheckAccessCommand forArm(ArmRun run, ArmEndpoint endpoint) {
        notRunnable(run).ifPresent(reason -> {
            throw new UnsupportedOperationException(reason);
        });
        return new CheckAccessCommand(endpoint.uri().toString(), endpoint.transport(),
                ScanAllCommands.auth(run.auth().headers()), useBurpNetworking, ArmIdentityCommands.of(run));
    }
}
