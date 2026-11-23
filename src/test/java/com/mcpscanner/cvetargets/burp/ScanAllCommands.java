package com.mcpscanner.cvetargets.burp;

import com.mcpscanner.auth.AuthHeaders;
import com.mcpscanner.auth.AuthStrategy;
import com.mcpscanner.automation.CommandAuth;
import com.mcpscanner.automation.CommandOAuthSession;
import com.mcpscanner.automation.ScanAllCommand;
import com.mcpscanner.automation.SeedCall;
import com.mcpscanner.cvetargets.manifest.SeedRequest;
import com.mcpscanner.cvetargets.oauth.HandsOverOAuthSession;
import com.mcpscanner.cvetargets.oauth.OAuthSessionHandover;
import com.mcpscanner.cvetargets.requests.ArmEndpoint;
import com.mcpscanner.cvetargets.run.ArmRun;

import java.util.Map;
import java.util.Optional;
import java.util.Set;

final class ScanAllCommands {

    private static final String BEARER_PREFIX = "Bearer ";
    private static final String IDENTITY_SEED_NOT_ROUTED =
            "Burp mode cannot send a seed as another identity yet";

    private final boolean useBurpNetworking;
    private final BurpAuditConfiguration configuration;
    private final boolean allChecks;

    ScanAllCommands(boolean useBurpNetworking, BurpAuditConfiguration configuration) {
        this(useBurpNetworking, configuration, false);
    }

    ScanAllCommands(boolean useBurpNetworking, BurpAuditConfiguration configuration, boolean allChecks) {
        this.useBurpNetworking = useBurpNetworking;
        this.configuration = configuration;
        this.allChecks = allChecks;
    }

    Optional<String> notRunnable(ArmRun run) {
        boolean routedSeed = run.target().manifest().baseSeeds().stream().anyMatch(SeedRequest::sentAsIdentity);
        return routedSeed ? Optional.of(IDENTITY_SEED_NOT_ROUTED) : Optional.empty();
    }

    ScanAllCommand forArm(ArmRun run, ArmEndpoint endpoint) {
        notRunnable(run).ifPresent(reason -> {
            throw new UnsupportedOperationException(reason);
        });
        return new ScanAllCommand(endpoint.uri().toString(), endpoint.transport(), primaryAuth(run.auth()),
                Set.of(allChecks ? ScanAllCommand.EVERY_CHECK : run.checkId()),
                run.target().manifest().baseSeeds().stream()
                        .map(seed -> new SeedCall(seed.method(), seed.params()))
                        .toList(),
                useBurpNetworking, configuration.divertsBuiltInChecks(), ArmIdentityCommands.of(run),
                run.target().manifest().maxCatalogItems(),
                SignedInSessionCommands.of(run.identities().signedInSession(), endpoint.uri()));
    }

    private static CommandAuth primaryAuth(AuthStrategy auth) {
        if (auth instanceof HandsOverOAuthSession oauth) {
            OAuthSessionHandover handover = oauth.handOver();
            return CommandAuth.handedOver(CommandOAuthSession.of(handover.accessToken(), handover.grant()));
        }
        return auth(auth.headers());
    }

    static CommandAuth auth(Map<String, String> headers) {
        String authorization = headers.get(AuthHeaders.AUTHORIZATION_HEADER);
        if (headers.size() == 1 && authorization != null && authorization.startsWith(BEARER_PREFIX)) {
            return new CommandAuth(authorization.substring(BEARER_PREFIX.length()), Map.of());
        }
        return new CommandAuth(null, headers);
    }
}
