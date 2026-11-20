package com.mcpscanner.cvetargets.burp;

import com.mcpscanner.auth.AuthStrategy;
import com.mcpscanner.auth.NoAuthStrategy;
import com.mcpscanner.checks.api.CheckDescriptor;
import com.mcpscanner.checks.api.McpCheck;
import com.mcpscanner.checks.api.RequestCheck;
import com.mcpscanner.cvetargets.environment.CommandResult;
import com.mcpscanner.cvetargets.identities.ArmIdentities;
import com.mcpscanner.cvetargets.identities.IdentityScripts;
import com.mcpscanner.cvetargets.manifest.LoadedTarget;
import com.mcpscanner.cvetargets.manifest.ManifestFixtures;
import com.mcpscanner.cvetargets.manifest.ProvisionedToken;
import com.mcpscanner.cvetargets.run.ArmRun;
import com.mcpscanner.logging.McpEventLog;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.net.URI;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;

import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

final class BurpArmFixtures {

    static final String CHECK = "example-check";

    private BurpArmFixtures() {
    }

    static ArmRun vulnerableArm(Path root, AuthStrategy auth) {
        String manifest = ManifestFixtures.VALID_MANIFEST.formatted("seeded-target", CHECK).replace(
                "\"auth\": { \"scheme\": \"none\" },",
                "\"auth\": { \"scheme\": \"none\" }, \"seeds\": [ { \"method\": \"tools/call\", "
                        + "\"params\": { \"name\": \"read\", \"arguments\": { \"path\": \"a.md\" } } } ],");
        ManifestFixtures.writeTarget(root, CHECK, "seeded-target", manifest);
        LoadedTarget target = ManifestFixtures.loadOnly(root, CHECK, "seeded-target");
        return ArmRun.asDeclared(target, target.manifest().arms().get(0), check(), auth);
    }

    static final String SIGNED_IN = """
            {"cookies": {"mcp_test_session": "s3ss10n"}, \
            "scannerClient": {"clientId": "mcp-server-scanner_AbCd", "clientName": "MCP Server Scanner", \
            "redirectUri": "http://127.0.0.1:47390/callback", "grantedScopes": ["mcp:tools"], \
            "softwareId": "mcp-server-scanner", "issuer": "http://127.0.0.1:41000", \
            "authorizationEndpoint": "http://127.0.0.1:41000/authorize", \
            "registrationEndpoint": "http://127.0.0.1:41000/register"}, \
            "headers": {"Authorization": "Bearer signed-in-token"}}
            """;

    static ArmRun signedInArm(Path root, URI endpoint) {
        String manifest = ManifestFixtures.VALID_MANIFEST.formatted("signed-in-target", CHECK).replace("\"arms\": [",
                "\"signedInSession\": { \"provision\": \"sign_in.py\" },\n  \"arms\": [");
        Path directory = ManifestFixtures.writeTarget(root, CHECK, "signed-in-target", manifest);
        try {
            Files.writeString(directory.resolve("sign_in.py"), "#!/bin/sh\n");
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
        LoadedTarget target = ManifestFixtures.loadOnly(root, CHECK, "signed-in-target");
        AuthStrategy primary = new ProvisionedToken().strategy();
        ArmIdentities identities = new ArmIdentities(target, "vulnerable", primary, IdentityScripts.using(
                (command, workingDirectory, timeout) -> new CommandResult(command, 0, SIGNED_IN), duration -> { }));
        identities.provision(endpoint, Duration.ofSeconds(1));
        return ArmRun.asDeclared(target, target.manifest().arms().get(0), check(), primary, identities,
                McpEventLog.noop());
    }

    static ArmRun fixedArm(Path root, AuthStrategy auth) {
        ArmRun vulnerable = vulnerableArm(root, auth);
        return ArmRun.asDeclared(vulnerable.target(), vulnerable.target().manifest().arms().get(1), vulnerable.check(),
                auth);
    }

    private static McpCheck check() {
        McpCheck check = mock(RequestCheck.class);
        CheckDescriptor descriptor = mock(CheckDescriptor.class);
        when(descriptor.id()).thenReturn(CHECK);
        when(check.descriptor()).thenReturn(descriptor);
        return check;
    }
}
