package com.mcpscanner.cvetargets.burp;

import com.mcpscanner.auth.AuthStrategy;
import com.mcpscanner.auth.BearerTokenAuthStrategy;
import com.mcpscanner.auth.CustomHeaderAuthStrategy;
import com.mcpscanner.auth.NoAuthStrategy;
import com.mcpscanner.auth.grant.ClientType;
import com.mcpscanner.auth.grant.OAuthClient;
import com.mcpscanner.auth.grant.RefreshGrant;
import com.mcpscanner.automation.CommandCookie;
import com.mcpscanner.automation.CommandOAuthSession;
import com.mcpscanner.automation.CommandScannerClient;
import com.mcpscanner.automation.ScanAllCommand;
import com.mcpscanner.automation.SignedInSessionCommand;
import com.mcpscanner.client.TransportType;
import com.mcpscanner.cvetargets.manifest.TargetManifest;
import com.mcpscanner.cvetargets.oauth.HandsOverOAuthSession;
import com.mcpscanner.cvetargets.oauth.OAuthSessionHandover;
import com.mcpscanner.cvetargets.requests.ArmEndpoint;
import com.mcpscanner.cvetargets.run.ArmBoundAuth;
import com.mcpscanner.cvetargets.run.ArmRun;
import com.mcpscanner.testutil.MontoyaTestFactory;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.net.URI;
import java.nio.file.Path;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;
import static org.mockito.Mockito.withSettings;

class ScanAllCommandsTest {

    private static final URI ENDPOINT = URI.create("http://127.0.0.1:41000/mcp");

    @TempDir
    Path root;

    private final ScanAllCommands commands = new ScanAllCommands(false, BurpAuditConfiguration.EXTENSIONS_ONLY);

    @BeforeEach
    void installMontoya() {
        MontoyaTestFactory.install();
    }

    @Test
    void scansTheArmEndpointWithOnlyTheArmsCheckAndTheManifestSeeds() {
        ScanAllCommand command = forArm(new NoAuthStrategy());

        assertThat(command.endpoint()).isEqualTo(ENDPOINT.toString());
        assertThat(command.transport()).isEqualTo(TransportType.STREAMABLE_HTTP);
        assertThat(command.checks()).containsExactly(BurpArmFixtures.CHECK);
        assertThat(command.seeds()).singleElement().satisfies(seed -> {
            assertThat(seed.method()).isEqualTo("tools/call");
            assertThat(seed.params().path("name").asText()).isEqualTo("read");
        });
        assertThat(command.useBurpNetworking()).isFalse();
        assertThat(command.divertBuiltInChecks()).isTrue();
        assertThat(command.auth().strategy().headers()).isEmpty();
        assertThat(command.maxCatalogItems()).isEqualTo(TargetManifest.DEFAULT_MAX_CATALOG_ITEMS);
    }

    @Test
    void withBuiltinsLetsBurpsOwnChecksReachTheTarget() {
        ScanAllCommand command = new ScanAllCommands(false, BurpAuditConfiguration.WITH_BUILTINS)
                .forArm(BurpArmFixtures.vulnerableArm(root, new NoAuthStrategy()),
                        new ArmEndpoint(ENDPOINT, new NoAuthStrategy(), TransportType.STREAMABLE_HTTP));

        assertThat(command.divertBuiltInChecks()).isFalse();
    }

    @Test
    void aBearerCredentialIsConfiguredAsBearerAuthentication() {
        ScanAllCommand command = forArm(new BearerTokenAuthStrategy("jwt-1"));

        assertThat(command.auth().bearerToken()).isEqualTo("jwt-1");
        assertThat(command.auth().headers()).isEmpty();
    }

    @Test
    void anyOtherHeadersAreConfiguredAsCustomHeaders() {
        ScanAllCommand command = forArm(new CustomHeaderAuthStrategy(Map.of(
                "Authorization", "Bearer jwt-1", "X-Upstream", "http://upstream.test")));

        assertThat(command.auth().bearerToken()).isNull();
        assertThat(command.auth().headers()).containsEntry("X-Upstream", "http://upstream.test")
                .containsEntry("Authorization", "Bearer jwt-1");
    }

    @Test
    void handsAHarnessObtainedOAuthSessionWithItsRefreshGrantToBurp() {
        RefreshGrant grant = new RefreshGrant(URI.create("http://127.0.0.1:41000"), Optional.of(ENDPOINT),
                new OAuthClient("client-1", Optional.of("secret-1"), ClientType.CONFIDENTIAL_REGISTERED),
                "refresh-1", List.of("mcp:tools"));

        ScanAllCommand command = forArm(harnessOAuth(new OAuthSessionHandover("access-1", Optional.of(grant))));

        assertThat(command.auth().oauthSession()).isEqualTo(new CommandOAuthSession("access-1", "refresh-1",
                URI.create("http://127.0.0.1:41000"), ENDPOINT, "client-1", "secret-1",
                ClientType.CONFIDENTIAL_REGISTERED, List.of("mcp:tools")));
        assertThat(command.auth().bearerToken()).isNull();
        assertThat(command.auth().headers()).isEmpty();
    }

    @Test
    void handsOverAnOAuthSessionWithoutARefreshTokenAsItsAccessTokenAlone() {
        ScanAllCommand command = forArm(harnessOAuth(new OAuthSessionHandover("access-1", Optional.empty())));

        assertThat(command.auth().oauthSession())
                .isEqualTo(new CommandOAuthSession("access-1", null, null, null, null, null, null, null));
    }

    @Test
    void allChecksAsksBurpToEnableEveryCatalogCheck() {
        ScanAllCommand command = new ScanAllCommands(false, BurpAuditConfiguration.EXTENSIONS_ONLY, true)
                .forArm(BurpArmFixtures.vulnerableArm(root, new NoAuthStrategy()),
                        new ArmEndpoint(ENDPOINT, new NoAuthStrategy(), TransportType.STREAMABLE_HTTP));

        assertThat(command.checks()).containsExactly(ScanAllCommand.EVERY_CHECK);
    }

    @Test
    void aHarnessObtainedOAuthArmIsRunnable() {
        AuthStrategy oauth = harnessOAuth(new OAuthSessionHandover("access-1", Optional.empty()));

        assertThat(commands.notRunnable(BurpArmFixtures.vulnerableArm(root, oauth))).isEmpty();
    }

    @Test
    void anArmWithASignedInSessionIsRunnable() {
        assertThat(commands.notRunnable(BurpArmFixtures.signedInArm(root, ENDPOINT))).isEmpty();
    }

    @Test
    void handsTheProvisionedSignedInSessionToBurpForTheArmsHost() {
        ScanAllCommand command = commands.forArm(BurpArmFixtures.signedInArm(root, ENDPOINT),
                new ArmEndpoint(ENDPOINT, new NoAuthStrategy(), TransportType.STREAMABLE_HTTP));

        SignedInSessionCommand session = command.signedInSession();
        assertThat(session.cookies()).containsExactly(new CommandCookie("127.0.0.1", "/", "mcp_test_session", "s3ss10n"));
        assertThat(session.optIn()).isTrue();
        assertThat(session.scannerClient()).isEqualTo(new CommandScannerClient(URI.create("http://127.0.0.1:41000"),
                URI.create("http://127.0.0.1:41000/authorize"), URI.create("http://127.0.0.1:41000/register"),
                "mcp-server-scanner_AbCd", "MCP Server Scanner", URI.create("http://127.0.0.1:47390/callback"),
                Set.of("mcp:tools"), "mcp-server-scanner"));
    }

    @Test
    void theSignedInUsersTokenIsThePrimaryBearer() {
        ArmRun signedIn = BurpArmFixtures.signedInArm(root, ENDPOINT);

        ScanAllCommand command = commands.forArm(signedIn,
                new ArmEndpoint(ENDPOINT, signedIn.auth(), TransportType.STREAMABLE_HTTP));

        assertThat(command.auth().bearerToken()).isEqualTo("signed-in-token");
    }

    @Test
    void anArmWithoutASignedInSessionHandsNoneOver() {
        assertThat(forArm(new NoAuthStrategy()).signedInSession()).isEqualTo(SignedInSessionCommand.NONE);
    }

    private static AuthStrategy harnessOAuth(OAuthSessionHandover handover) {
        AuthStrategy oauth = mock(AuthStrategy.class,
                withSettings().extraInterfaces(ArmBoundAuth.class, HandsOverOAuthSession.class));
        when(((HandsOverOAuthSession) oauth).handOver()).thenReturn(handover);
        return oauth;
    }

    private ScanAllCommand forArm(AuthStrategy auth) {
        return commands.forArm(BurpArmFixtures.vulnerableArm(root, auth),
                new ArmEndpoint(ENDPOINT, auth, TransportType.STREAMABLE_HTTP));
    }
}
