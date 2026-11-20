package com.mcpscanner.cvetargets.identities;

import com.mcpscanner.ExtensionMetadata;
import com.mcpscanner.auth.AuthStrategy;
import com.mcpscanner.auth.NoAuthStrategy;
import com.mcpscanner.checks.api.RegisteredClientName;
import com.mcpscanner.checks.api.ScannerClient;
import com.mcpscanner.checks.api.SignedInConsent;
import com.mcpscanner.cvetargets.environment.CommandResult;
import com.mcpscanner.cvetargets.environment.CommandRunner;
import com.mcpscanner.cvetargets.manifest.LoadedTarget;
import com.mcpscanner.cvetargets.manifest.ManifestFixtures;
import com.mcpscanner.cvetargets.manifest.ProvisionedToken;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.IOException;
import java.net.URI;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class ArmSignedInConsentTest {

    private static final URI ENDPOINT = URI.create("http://127.0.0.1:4100/mcp");
    private static final URI AUTHORIZATION_ENDPOINT = URI.create("http://127.0.0.1:4100/authorize");
    private static final Duration TIMEOUT = Duration.ofSeconds(30);
    private static final String SCRIPT = "sign_in.py";
    private static final String SIGNED_IN = """
            signed in as test-user
            {"cookies": {"mcp_test_session": "s3ss10n"}, \
            "scannerClient": {"clientId": "mcp-server-scanner_AbCdEfGh12345678", "clientName": "MCP Server Scanner", \
            "redirectUri": "http://127.0.0.1:47390/callback", "grantedScopes": ["mcp:tools"], \
            "softwareId": "mcp-server-scanner", "issuer": "http://127.0.0.1:4100", \
            "authorizationEndpoint": "http://127.0.0.1:4100/authorize", \
            "registrationEndpoint": "http://127.0.0.1:4100/register"}, \
            "headers": {"Authorization": "Bearer signed-in-token"}}
            """;

    @TempDir
    Path root;

    private final List<List<String>> commands = new ArrayList<>();
    private int failures;

    @Test
    void handsTheProvisionedCookiesToTheAuthorizationServerOnTheArmsOriginOnly() throws IOException {
        ArmIdentities identities = provisioned(new NoAuthStrategy());

        SignedInConsent consent = identities.signedInConsent();

        assertThat(consent.optedIn()).isTrue();
        assertThat(consent.cookieSession(AUTHORIZATION_ENDPOINT)).hasValueSatisfying(session ->
                assertThat(session.cookies()).containsExactly(
                        new com.mcpscanner.checks.shared.oauth.SessionCookie("mcp_test_session", "s3ss10n", "/")));
        assertThat(consent.cookieSession(URI.create("http://127.0.0.1:4101/authorize"))).isEmpty();
        assertThat(consent.cookieSession(URI.create("https://idp.example/authorize"))).isEmpty();
        assertThat(consent.browserObservations(AUTHORIZATION_ENDPOINT)).isEmpty();
        assertThat(commands).singleElement().isEqualTo(List.of(
                root.resolve("check-a/signed-in/" + SCRIPT).toString(), ENDPOINT.toString(),
                ExtensionMetadata.SOFTWARE_ID));
    }

    @Test
    void describesTheScannerClientTheScriptRegisteredAndApproved() throws IOException {
        SignedInConsent consent = provisioned(new NoAuthStrategy()).signedInConsent();

        assertThat(consent.scannerClient()).contains(new ScannerClient(URI.create("http://127.0.0.1:4100"),
                "mcp-server-scanner_AbCdEfGh12345678",
                RegisteredClientName.of("MCP Server Scanner"), URI.create("http://127.0.0.1:47390/callback"), Set.of("mcp:tools"),
                Optional.of("mcp-server-scanner")));
    }

    @Test
    void givesAProvisionedPrimaryCredentialTheSignedInUsersHeaders() throws IOException {
        AuthStrategy primary = new ProvisionedToken().strategy();

        provisioned(primary);

        assertThat(primary.headers()).containsExactly(Map.entry("Authorization", "Bearer signed-in-token"));
    }

    @Test
    void retriesTheScriptUntilTheServerSignsTheUserIn() throws IOException {
        failures = 2;

        provisioned(new NoAuthStrategy());

        assertThat(commands).hasSize(3);
    }

    @Test
    void failsTheArmWhenTheScriptNeverSucceeds() throws IOException {
        failures = Integer.MAX_VALUE;
        ArmIdentities identities = identities(withSignedInSession(), new NoAuthStrategy());

        assertThatThrownBy(() -> identities.provision(ENDPOINT, Duration.ZERO))
                .hasMessageContaining("signed-in session provisioning failed")
                .hasMessageContaining("not signed in");
    }

    @Test
    void staysOptedOutWithoutASignedInSession() {
        ManifestFixtures.writeValidTarget(root, "check-a", "plain");
        ArmIdentities identities = identities(ManifestFixtures.loadOnly(root, "check-a", "plain"), new NoAuthStrategy());

        identities.provision(ENDPOINT, TIMEOUT);

        assertThat(identities.signedInConsent()).isSameAs(SignedInConsent.OPTED_OUT);
        assertThat(commands).isEmpty();
    }

    @Test
    void offersNoSessionBeforeTheScriptHasRun() throws IOException {
        SignedInConsent consent = identities(withSignedInSession(), new NoAuthStrategy()).signedInConsent();

        assertThat(consent.optedIn()).isTrue();
        assertThat(consent.cookieSession(AUTHORIZATION_ENDPOINT)).isEmpty();
        assertThat(consent.scannerClient()).isEmpty();
    }

    private ArmIdentities provisioned(AuthStrategy primary) throws IOException {
        ArmIdentities identities = identities(withSignedInSession(), primary);
        identities.provision(ENDPOINT, TIMEOUT);
        return identities;
    }

    private ArmIdentities identities(LoadedTarget target, AuthStrategy primary) {
        CommandRunner runner = (command, directory, timeout) -> {
            commands.add(command);
            return failures-- > 0 ? new CommandResult(command, 1, "not signed in yet")
                    : new CommandResult(command, 0, SIGNED_IN);
        };
        return new ArmIdentities(target, "vulnerable", primary, IdentityScripts.using(runner, duration -> { }));
    }

    private LoadedTarget withSignedInSession() throws IOException {
        String manifest = ManifestFixtures.VALID_MANIFEST.formatted("signed-in", "check-a")
                .replace("\"arms\": [", "\"signedInSession\": { \"provision\": \"" + SCRIPT + "\" },\n  \"arms\": [");
        Path directory = ManifestFixtures.writeTarget(root, "check-a", "signed-in", manifest);
        Files.writeString(directory.resolve(SCRIPT), "#!/bin/sh\n");
        return ManifestFixtures.loadOnly(root, "check-a", "signed-in");
    }
}
