package com.mcpscanner.checks.catalog.oauthredirectpolicy;

import com.mcpscanner.checks.catalog.oauthredirectpolicy.FakeAuthorizationServer.RegistrationReply;
import com.mcpscanner.testutil.MontoyaTestFactory;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

class ScriptSchemeRegistrationProbeTest {

    private FakeAuthorizationServer server;

    @BeforeEach
    void setUp() {
        MontoyaTestFactory.install();
        server = new FakeAuthorizationServer();
    }

    private List<RedirectFinding> run() {
        return new ScriptSchemeRegistrationProbe().run(server.probeContext());
    }

    private List<String> attemptedRedirectUris() {
        return server.registrations().stream()
                .flatMap(request -> FakeAuthorizationServer.registeredRedirectUris(request).stream())
                .toList();
    }

    private static RegistrationReply httpsOnly(List<String> uris, RegistrationReply otherwise) {
        return uris.get(0).startsWith("https:") ? RegistrationReply.ECHO : otherwise;
    }

    @Test
    void reportsNothingWithoutAnHttpsControlRegistration() {
        server.registering(uris -> RegistrationReply.REJECT);

        assertThat(run()).isEmpty();
        assertThat(server.registrations()).hasSize(1);
    }

    @Test
    void reportsEachLowercaseScriptSchemeThatIsAcceptedAndEchoed() {
        List<RedirectFinding> findings = run();

        assertThat(findings).extracting(RedirectFinding::summary).containsExactly(
                "registered and echoed javascript:void(0)", "registered and echoed data:text/html,scancheck");
        assertThat(findings).extracting(RedirectFinding::kind).containsOnly(FindingKind.SCRIPT_SCHEME_REGISTRATION);
        assertThat(findings).extracting(RedirectFinding::location)
                .containsOnly(FakeAuthorizationServer.REGISTRATION_ENDPOINT);
    }

    @Test
    void doesNotRetryMixedCaseAfterLowercaseIsAccepted() {
        run();

        assertThat(attemptedRedirectUris()).doesNotContain("JavaScript:void(0)", "Data:text/html,scancheck");
    }

    @Test
    void findingEvidenceIsOnlyTheAcceptedScriptRegistration() {
        RedirectFinding finding = run().get(0);

        assertThat(finding.evidence()).singleElement().satisfies(exchange ->
                assertThat(FakeAuthorizationServer.registeredRedirectUris(exchange.request()))
                        .containsExactly("javascript:void(0)"));
    }

    @Test
    void retriesMixedCaseAfterAnExplicitRejection() {
        server.registering(uris -> uris.get(0).startsWith("javascript:") || uris.get(0).startsWith("data:")
                ? RegistrationReply.REJECT : RegistrationReply.ECHO);

        assertThat(run()).extracting(RedirectFinding::summary).containsExactly(
                "registered and echoed JavaScript:void(0)", "registered and echoed Data:text/html,scancheck");
    }

    @Test
    void doesNotRetryMixedCaseAfterAnInconclusiveFailure() {
        server.registering(uris -> httpsOnly(uris, RegistrationReply.FAIL));

        assertThat(run()).isEmpty();
        assertThat(attemptedRedirectUris()).doesNotContain("JavaScript:void(0)", "Data:text/html,scancheck");
    }

    @Test
    void doesNotReportOrRetryWhenAcceptedWithoutEcho() {
        server.registering(uris -> httpsOnly(uris, RegistrationReply.OMIT_REDIRECT_URIS));

        assertThat(run()).isEmpty();
        assertThat(attemptedRedirectUris()).doesNotContain("JavaScript:void(0)", "Data:text/html,scancheck");
    }

    @Test
    void reportsNothingWhenEverySpellingIsRejected() {
        server.registering(uris -> httpsOnly(uris, RegistrationReply.REJECT));

        assertThat(run()).isEmpty();
        assertThat(attemptedRedirectUris()).contains(
                "javascript:void(0)", "JavaScript:void(0)", "data:text/html,scancheck", "Data:text/html,scancheck");
    }
}
