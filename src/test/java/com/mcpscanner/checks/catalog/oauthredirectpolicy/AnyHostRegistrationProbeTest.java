package com.mcpscanner.checks.catalog.oauthredirectpolicy;

import com.mcpscanner.checks.catalog.oauthredirectpolicy.FakeAuthorizationServer.RegistrationReply;
import com.mcpscanner.testutil.MontoyaTestFactory;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

class AnyHostRegistrationProbeTest {

    private FakeAuthorizationServer server;

    @BeforeEach
    void setUp() {
        MontoyaTestFactory.install();
        server = new FakeAuthorizationServer();
    }

    private List<RedirectFinding> run() {
        return new AnyHostRegistrationProbe().run(server.probeContext());
    }

    @Test
    void reportsAnAnonymousRegistrationThatEchoesTheThirdPartyHttpsRedirectUri() {
        List<RedirectFinding> findings = run();

        assertThat(findings).singleElement().satisfies(finding -> {
            assertThat(finding.kind()).isEqualTo(FindingKind.ANY_HOST_REGISTRATION);
            assertThat(finding.location()).isEqualTo(FakeAuthorizationServer.REGISTRATION_ENDPOINT);
            assertThat(finding.summary()).matches(
                    "registered and echoed https://client\\.example\\.com/scancheck-control-[0-9a-f-]+");
        });
    }

    @Test
    void sendsNoRequestBeyondTheSharedHttpsControlRegistration() {
        run();

        assertThat(server.registrations()).singleElement().satisfies(request ->
                assertThat(FakeAuthorizationServer.registeredRedirectUris(request)).singleElement()
                        .asString().startsWith("https://client.example.com/"));
    }

    @Test
    void registersAnonymously() {
        run();

        assertThat(server.registrations()).singleElement()
                .satisfies(request -> assertThat(request.headerValue("Authorization")).isNull());
    }

    @Test
    void evidenceIsTheRegistrationExchange() {
        RedirectFinding finding = run().get(0);

        assertThat(finding.evidence()).singleElement().satisfies(exchange -> {
            assertThat(exchange.request().url()).isEqualTo(FakeAuthorizationServer.REGISTRATION_ENDPOINT.toString());
            assertThat(exchange.response().statusCode()).isEqualTo((short) 201);
        });
    }

    @Test
    void keepsTheRegistrationAccessTokenAndClientSecretRawInTheEvidence() {
        server.managingClients().withClientSecrets();

        String response = run().get(0).evidence().get(0).response().bodyToString();

        assertThat(response).contains("rat-client-1", "secret-client-1");
    }

    @Test
    void keepsARegistrationAccessTokenWhoseManagementUriIsOnAnotherOriginRaw() {
        server.issuingUnmanagedRegistrationTokens();

        String response = run().get(0).evidence().get(0).response().bodyToString();

        assertThat(response).contains("rat-client-1");
    }

    @Test
    void reportsNothingWhenRegistrationIsRefused() {
        server.registering(uris -> RegistrationReply.REJECT);

        assertThat(run()).isEmpty();
    }

    @Test
    void reportsNothingWhenRegistrationNeedsAuthentication() {
        server.registering(uris -> RegistrationReply.UNAUTHORIZED);

        assertThat(run()).isEmpty();
    }

    @Test
    void reportsNothingWhenRegistrationDropsTheRedirectUri() {
        server.registering(uris -> RegistrationReply.OMIT_REDIRECT_URIS);

        assertThat(run()).isEmpty();
    }

    @Test
    void reportsNothingWhenRegistrationRewritesTheRedirectUri() {
        server.registering(uris -> RegistrationReply.REWRITE_REDIRECT_URIS);

        assertThat(run()).isEmpty();
    }
}
