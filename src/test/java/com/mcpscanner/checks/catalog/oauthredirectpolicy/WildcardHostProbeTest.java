package com.mcpscanner.checks.catalog.oauthredirectpolicy;

import com.mcpscanner.checks.catalog.oauthredirectpolicy.FakeAuthorizationServer.AuthorizationReply;
import com.mcpscanner.checks.catalog.oauthredirectpolicy.FakeAuthorizationServer.RegistrationReply;
import com.mcpscanner.testutil.MontoyaTestFactory;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.net.URI;
import java.util.List;
import java.util.regex.Pattern;

import static org.assertj.core.api.Assertions.assertThat;

class WildcardHostProbeTest {

    private FakeAuthorizationServer server;

    @BeforeEach
    void setUp() {
        MontoyaTestFactory.install();
        server = new FakeAuthorizationServer();
    }

    private List<RedirectFinding> run() {
        return new WildcardHostProbe().run(server.probeContext());
    }

    private static boolean matchesAny(String redirectUri, List<String> registered) {
        return registered.stream().anyMatch(pattern ->
                redirectUri.matches(Pattern.quote(pattern).replace("*", "\\E[^./]+\\Q")));
    }

    private void expandWildcardsAndOtherwise(AuthorizationReply otherwise) {
        server.redirecting((redirectUri, registered) -> matchesAny(redirectUri, registered)
                ? AuthorizationReply.DELIVER : otherwise);
    }

    @Test
    void reportsNothingWithoutAnHttpsControlClient() {
        server.registering(uris -> RegistrationReply.FAIL);

        assertThat(run()).isEmpty();
        assertThat(server.registrations()).hasSize(1);
    }

    @Test
    void registersTheControlAndTheWildcardPatternTogether() {
        run();

        assertThat(FakeAuthorizationServer.registeredRedirectUris(server.registrations().get(1)))
                .satisfiesExactly(
                        control -> assertThat(control).startsWith("https://client.example.com/scancheck-control-"),
                        pattern -> assertThat(pattern).startsWith("https://*.client.example.com/scancheck-wildcard-"));
    }

    @Test
    void reportsNothingWhenTheWildcardRegistrationIsRejected() {
        server.registering(uris -> uris.size() > 1 ? RegistrationReply.REJECT : RegistrationReply.ECHO);

        assertThat(run()).isEmpty();
        assertThat(server.authorizations()).isEmpty();
    }

    @Test
    void reportsNothingWhenTheWildcardIsNotEchoed() {
        server.registering(uris -> uris.size() > 1 ? RegistrationReply.OMIT_REDIRECT_URIS : RegistrationReply.ECHO);

        assertThat(run()).isEmpty();
        assertThat(server.authorizations()).isEmpty();
    }

    @Test
    void reportsExpansionWhenTheMatchingHostGetsACodeAndTheUnmatchedHostIsRejected() {
        expandWildcardsAndOtherwise(AuthorizationReply.REJECT);

        List<RedirectFinding> findings = run();

        assertThat(findings).singleElement().satisfies(finding -> {
            assertThat(finding.kind()).isEqualTo(FindingKind.WILDCARD_EXPANSION);
            assertThat(finding.location()).isEqualTo(FakeAuthorizationServer.AUTHORIZATION_ENDPOINT);
            assertThat(finding.summary())
                    .contains(".client.example.com/scancheck-wildcard-")
                    .contains("matched only by https://*.client.example.com/scancheck-wildcard-")
                    .contains(".example.org/scancheck-wildcard-")
                    .contains(".client.example.com/scancheck-unlisted-")
                    .endsWith("were rejected");
        });
    }

    @Test
    void expansionEvidenceIsRegistrationControlOnceThenTheThreeProbes() {
        expandWildcardsAndOtherwise(AuthorizationReply.REJECT);

        RedirectFinding finding = run().get(0);

        assertThat(FakeAuthorizationServer.registeredRedirectUris(finding.evidence().get(0).request()))
                .anySatisfy(pattern -> assertThat(pattern).startsWith("https://*.client.example.com/"));
        assertThat(finding.evidence().subList(1, finding.evidence().size()))
                .extracting(exchange -> QueryParameters.of(exchange.request().url()).get("redirect_uri"))
                .satisfiesExactly(
                        control -> assertThat(control).startsWith("https://client.example.com/scancheck-control-"),
                        matched -> assertThat(matched).contains(".client.example.com/scancheck-wildcard-"),
                        unmatchedHost -> assertThat(unmatchedHost).contains(".example.org/scancheck-wildcard-"),
                        unmatchedPath -> assertThat(unmatchedPath).contains(".client.example.com/scancheck-unlisted-"));
    }

    @Test
    void reportsNothingWhenTheServerMatchesExactly() {
        assertThat(run()).isEmpty();
    }

    @Test
    void doesNotProbeTheUnmatchedHostWhenTheMatchingHostGetsNoCode() {
        assertThat(run()).isEmpty();
        assertThat(server.authorizations()).hasSize(2);
    }

    @Test
    void reportsNothingWhenTheMatchingHostGetsOnlyAnError() {
        server.redirecting((redirectUri, registered) -> registered.contains(redirectUri)
                ? AuthorizationReply.DELIVER
                : matchesAny(redirectUri, registered) ? AuthorizationReply.DELIVER_ERROR : AuthorizationReply.REJECT);

        assertThat(run()).isEmpty();
        assertThat(server.authorizations()).hasSize(2);
    }

    @Test
    void reportsNothingWhenTheUnmatchedHostAlsoGetsACode() {
        server.redirecting(FakeAuthorizationServer.anyRedirect());

        assertThat(run()).isEmpty();
        assertThat(server.authorizations()).hasSize(4);
    }

    @Test
    void reportsNothingWhenTheServerAcceptsAnyPathOnASubdomainOfTheRegisteredHost() {
        server.redirecting((redirectUri, registered) -> registered.contains(redirectUri)
                || URI.create(redirectUri).getHost().endsWith(".client.example.com")
                ? AuthorizationReply.DELIVER : AuthorizationReply.REJECT);

        assertThat(run()).isEmpty();
    }

    @Test
    void reportsNothingWhenTheUnmatchedHostIsInconclusive() {
        expandWildcardsAndOtherwise(AuthorizationReply.FAIL);

        assertThat(run()).isEmpty();
    }
}
