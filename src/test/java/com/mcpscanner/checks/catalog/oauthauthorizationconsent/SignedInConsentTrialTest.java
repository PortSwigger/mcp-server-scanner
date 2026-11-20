package com.mcpscanner.checks.catalog.oauthauthorizationconsent;

import burp.api.montoya.http.message.HttpHeader;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.scanner.audit.issues.AuditIssue;
import burp.api.montoya.scanner.audit.issues.AuditIssueConfidence;
import burp.api.montoya.scanner.audit.issues.AuditIssueSeverity;
import com.mcpscanner.auth.BearerTokenAuthStrategy;
import com.mcpscanner.checks.api.BrowserConsentObservation;
import com.mcpscanner.checks.api.HostAudits;
import com.mcpscanner.checks.api.HostTrial;
import com.mcpscanner.checks.api.RegisteredClientName;
import com.mcpscanner.checks.api.ScannerClient;
import com.mcpscanner.checks.api.SignedInConsent;
import com.mcpscanner.checks.api.SignedInProbe;
import com.mcpscanner.checks.api.SkipReason;
import com.mcpscanner.checks.shared.oauth.ClientSecret;
import com.mcpscanner.checks.shared.oauth.ClientSecretMethod;
import com.mcpscanner.checks.shared.oauth.ScriptedHttp;
import com.mcpscanner.logging.McpEventLog;
import com.mcpscanner.performance.RequestBudgets;
import com.mcpscanner.testutil.MontoyaTestFactory;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import java.net.URI;
import java.time.Duration;
import java.util.Arrays;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import static com.mcpscanner.checks.catalog.oauthauthorizationconsent.SignedInServer.AUTHORIZE;
import static com.mcpscanner.checks.catalog.oauthauthorizationconsent.SignedInServer.MCP;
import static com.mcpscanner.checks.catalog.oauthauthorizationconsent.SignedInServer.SCANNER_NAME;
import static com.mcpscanner.checks.catalog.oauthauthorizationconsent.SignedInServer.SCANNER_REDIRECT;
import static com.mcpscanner.checks.catalog.oauthauthorizationconsent.SignedInServer.SESSION_COOKIE;
import static com.mcpscanner.checks.catalog.oauthauthorizationconsent.SignedInServer.TRANSACTION_COOKIE;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.mockingDetails;

class SignedInConsentTrialTest {

    private static final String ANY_CLIENT = "MCP OAuth consent skipped for signed-in user";
    private static final String BY_NAME = "MCP OAuth consent remembered by client name";
    private static final String BY_REDIRECT_HOST = "MCP OAuth consent remembered by redirect host";
    private static final String BY_PREFIX = "MCP OAuth consent remembered by client_id prefix";
    private static final String BROADER_SCOPE = "MCP OAuth consent not re-asked for broader scope";
    private static final String PREFIXED_SCANNER_ID = "burp-mcp_a1b2c3d4e5f6";
    private static final String TOOLS_LIST = "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/list\"}";

    private final McpEventLog eventLog = mock(McpEventLog.class);
    private SignedInServer server;
    private FakeSignedInConsent consent;

    @BeforeEach
    void setUp() {
        MontoyaTestFactory.install();
        server = new SignedInServer();
        consent = new FakeSignedInConsent();
    }

    private static HttpRequestResponse base() {
        return HttpRequestResponse.httpRequestResponse(HttpRequest.httpRequestFromUrl(MCP).withMethod("POST")
                .withBody(TOOLS_LIST)
                .withAddedHeader("Content-Type", "application/json")
                .withAddedHeader("Authorization", "Bearer scanner-token"), null);
    }

    private OAuthAuthorizationConsentCheck check(SignedInConsent signedIn) {
        return new OAuthAuthorizationConsentCheck(eventLog, () -> new BearerTokenAuthStrategy("scanner-token"),
                signedIn);
    }

    private HostTrial trial() {
        return check(consent).trials().stream().filter(SignedInConsentTrial.class::isInstance).findFirst()
                .orElseThrow();
    }

    private List<AuditIssue> run() {
        return trial().run(base(), server.http().http()).issues();
    }

    private static List<String> names(List<AuditIssue> issues) {
        return issues.stream().map(AuditIssue::name).toList();
    }

    private List<String> logged() {
        return mockingDetails(eventLog).getInvocations().stream()
                .flatMap(invocation -> Arrays.stream(invocation.getArguments()))
                .map(String::valueOf)
                .toList();
    }

    private void assertLogged(String text) {
        assertThat(logged()).anySatisfy(line -> assertThat(line).contains(text));
    }

    private static String rendered(HttpRequestResponse exchange) {
        String request = exchange.request().url() + exchange.request().headers().stream().map(HttpHeader::toString)
                .collect(Collectors.joining()) + exchange.request().bodyToString();
        return exchange.response() == null ? request : request + exchange.response().headers().stream()
                .map(HttpHeader::toString).collect(Collectors.joining()) + exchange.response().bodyToString();
    }

    private static String prefixedIds(SignedInServer.Client client) {
        return client.softwareId().map(id -> id + "_" + UUID.randomUUID().toString().replace("-", "").substring(0, 12))
                .orElseGet(() -> UUID.randomUUID().toString());
    }

    @Nested
    class BenignServer {

        @Test
        void aServerThatAsksForEveryNewClientAndEveryWiderScopeIsSilent() {
            assertThat(run()).isEmpty();
            assertThat(server.registrations()).hasSize(3);
        }

        @Test
        void everyProbeClientIsDeletedAndNoTokenIsLeft() {
            run();

            assertThat(server.deletedClients()).containsExactlyInAnyOrderElementsOf(server.registeredIds());
            assertThat(server.http().sentTo(SignedInServer.TOKEN)).isEmpty();
        }

        @Test
        void staysWithinTheRequestBudget() {
            run();

            RequestBudgets.assertWithin("Signed-in consent trial, benign server", server.http().sentUrls());
        }

        @Test
        void sendsTheSessionCookiesAndTheCookiesSetAlongTheWay() {
            run();

            assertThat(server.http().sentTo(SignedInServer.DECIDE)).isNotEmpty().allSatisfy(request ->
                    assertThat(request.headerValue("Cookie"))
                            .isEqualTo("sid=" + SESSION_COOKIE + "; tx=" + TRANSACTION_COOKIE));
        }

        @Test
        void neverLogsACookieValue() {
            run();

            assertThat(logged()).noneSatisfy(line -> assertThat(line).contains(SESSION_COOKIE));
            assertThat(logged()).noneSatisfy(line -> assertThat(line).contains(TRANSACTION_COOKIE));
        }
    }

    @Nested
    class AnyClient {

        @BeforeEach
        void autoApprove() {
            server.rememberWhen((client, scopes) -> true);
        }

        @Test
        void aCodeForAFreshClientIsHighAndCertainWhenItsTokenOpensTheEndpoint() {
            AuditIssue issue = run().get(0);

            assertThat(issue.name()).isEqualTo(ANY_CLIENT);
            assertThat(issue.severity()).isEqualTo(AuditIssueSeverity.HIGH);
            assertThat(issue.confidence()).isEqualTo(AuditIssueConfidence.CERTAIN);
            assertThat(issue.detail()).contains(FakeSignedInConsent.SOURCE).contains("HTTP 401");
        }

        @Test
        void subsumesEveryOtherProbeAndSendsNothingMore() {
            assertThat(names(run())).containsExactly(ANY_CLIENT);

            assertThat(server.registrations()).hasSize(1);
            assertThat(server.http().sentTo(AUTHORIZE)).hasSize(1);
            assertThat(logged().stream().filter(line -> line.contains("subsumed"))).hasSize(4);
        }

        @Test
        void aTokenThatDoesNotOpenTheEndpointLeavesTheFindingFirm() {
            server.http().on("POST", MCP, ScriptedResponses.UNAUTHORIZED);

            assertThat(run().get(0).confidence()).isEqualTo(AuditIssueConfidence.FIRM);
        }

        @Test
        void keepsTheRawExchangesWithTheSessionCookieAsEvidence() {
            List<String> evidence = run().get(0).requestResponses().stream()
                    .map(SignedInConsentTrialTest::rendered).toList();

            assertThat(evidence).anySatisfy(exchange -> assertThat(exchange).contains(SESSION_COOKIE));
        }

        @Test
        void revokesTheTokenAndDeletesTheClient() {
            run();

            assertThat(server.revokedTokens()).containsExactly("token-code-1");
            assertThat(server.deletedClients()).containsExactlyElementsOf(server.registeredIds());
        }

        @Test
        void deletesTheClientsEvenWhenRevocationFails() {
            server.http().on("POST", SignedInServer.REVOKE, request -> {
                throw new IllegalStateException("connection reset");
            });

            assertThatThrownBy(SignedInConsentTrialTest.this::run).isInstanceOf(IllegalStateException.class);
            assertThat(server.deletedClients()).containsExactlyElementsOf(server.registeredIds());
        }

        @Test
        void cleansUpWhenTheJudgementFails() {
            server.http().on("POST", MCP, request -> {
                if (request.hasHeader("Authorization")) {
                    throw new IllegalStateException("connection reset");
                }
                return ScriptedResponses.UNAUTHORIZED;
            });

            assertThatThrownBy(SignedInConsentTrialTest.this::run).isInstanceOf(IllegalStateException.class);
            assertThat(server.revokedTokens()).containsExactly("token-code-1");
            assertThat(server.deletedClients()).containsExactlyElementsOf(server.registeredIds());
        }
    }

    @Nested
    class RememberedKeys {

        @Test
        void consentRememberedByClientNameIsReportedForTheNameAlone() {
            server.rememberWhen((client, scopes) -> SignedInServer.rememberedPerClientAndScope(client, scopes)
                    || !client.id().equals(SignedInServer.SCANNER_ID) && client.name().equals(SCANNER_NAME));

            List<AuditIssue> issues = run();

            assertThat(names(issues)).containsExactly(BY_NAME);
            assertThat(issues.get(0).severity()).isEqualTo(AuditIssueSeverity.HIGH);
            assertThat(issues.get(0).confidence()).isEqualTo(AuditIssueConfidence.CERTAIN);
            assertThat(server.deletedClients()).containsExactlyInAnyOrderElementsOf(server.registeredIds());
        }

        @Test
        void consentRememberedByRedirectHostIsReportedForAnotherPortAndPath() {
            server.rememberWhen((client, scopes) -> SignedInServer.rememberedPerClientAndScope(client, scopes)
                    || !client.id().equals(SignedInServer.SCANNER_ID)
                    && client.redirect().getHost().equals(SCANNER_REDIRECT.getHost()));

            assertThat(names(run())).containsExactly(BY_REDIRECT_HOST);
            assertThat(server.http().sentTo(SignedInServer.TOKEN)).singleElement().satisfies(redemption ->
                    assertThat(redemption.bodyToString()).contains("127.0.0.1%3A49151")
                            .doesNotContain("callback"));
        }

        @Test
        void consentRememberedByClientIdPrefixIsReportedForAClientCarryingTheSoftwareId() {
            consent.withScannerClient(Optional.of(FakeSignedInConsent.scannerClient(PREFIXED_SCANNER_ID)));
            server.mintClientIds(SignedInConsentTrialTest::prefixedIds)
                    .rememberWhen((client, scopes) -> client.id().startsWith("burp-mcp_"));

            assertThat(names(run())).containsExactly(BY_PREFIX);
            assertThat(server.registrations().get(3).bodyToString()).contains("\"software_id\":\"burp-mcp\"");
        }
    }

    @Nested
    class ScopeUpgrade {

        @BeforeEach
        void rememberOnlyTheScannerClientWhateverTheScope() {
            server.rememberWhen((client, scopes) -> client.id().equals(SignedInServer.SCANNER_ID));
        }

        @Test
        void aTokenGrantingTheExtraScopesIsMediumAndFirm() {
            List<AuditIssue> issues = run();

            assertThat(names(issues)).containsExactly(BROADER_SCOPE);
            assertThat(issues.get(0).severity()).isEqualTo(AuditIssueSeverity.MEDIUM);
            assertThat(issues.get(0).confidence()).isEqualTo(AuditIssueConfidence.FIRM);
            assertThat(issues.get(0).detail()).contains("read write admin")
                    .contains("control code issued at the granted scope was not redeemed");
        }

        @Test
        void redeemsTheUpgradeCodeOnceAsAPublicClientAndRevokesWhatItObtained() {
            run();

            assertThat(server.redemptionsBy(SignedInServer.SCANNER_ID)).singleElement().satisfies(redemption ->
                    assertThat(redemption.bodyToString()).contains("code_verifier=")
                            .contains("redirect_uri=http%3A%2F%2F127.0.0.1%3A8765%2Fcallback")
                            .doesNotContain("client_secret"));
            assertThat(server.revokedTokens()).containsExactly("token-code-2");
        }

        @Test
        void aConfidentialScannerClientRedeemsWithConnectsSecretAndIsFirm() {
            server.scannerClientIsConfidentialWith("connect-secret");
            consent.withScannerClient(Optional.of(FakeSignedInConsent.scannerClient(SignedInServer.SCANNER_ID)
                    .withSecret(new ClientSecret("connect-secret", ClientSecretMethod.BASIC))));

            List<AuditIssue> issues = run();

            assertThat(names(issues)).containsExactly(BROADER_SCOPE);
            assertThat(issues.get(0).confidence()).isEqualTo(AuditIssueConfidence.FIRM);
            assertThat(issues.get(0).detail()).contains("authenticated with the client_secret Connect used");
            assertThat(server.revokedTokens()).containsExactly("token-code-2");
        }

        @Test
        void aServerThatNarrowsTheScopeIsNotReported() {
            server.answerTokenScope(requested -> Optional.of("read"));

            assertThat(run()).isEmpty();
            assertLogged("the server narrowed the scope to \"read\"");
        }

        @Test
        void aTokenResponseWithoutScopeIsTentative() {
            server.answerTokenScope(requested -> Optional.empty());

            AuditIssue issue = run().get(0);

            assertThat(issue.confidence()).isEqualTo(AuditIssueConfidence.TENTATIVE);
            assertThat(issue.detail()).contains("The granted scope could not be read");
        }

        @Test
        void aRefusedRedemptionIsTentative() {
            server.http().on("POST", SignedInServer.TOKEN, ScriptedHttp.json(401, "{\"error\":\"invalid_client\"}"));

            AuditIssue issue = run().get(0);

            assertThat(issue.confidence()).isEqualTo(AuditIssueConfidence.TENTATIVE);
            assertThat(issue.detail()).contains("The granted scope could not be read");
        }

        @Test
        void openIdConnectScopesAreNeverTheExtraScopes() {
            server.advertiseScopes("[\"read\",\"openid\",\"profile\",\"email\",\"address\",\"phone\",\"write\"]");

            run();

            assertThat(server.requestedScopes(SignedInServer.SCANNER_ID)).containsExactly("read", "read write");
        }

        @Test
        void onlyOpenIdConnectScopesBeyondTheGrantedOnesAreNotProbed() {
            server.advertiseScopes("[\"read\",\"openid\",\"profile\"]");

            assertThat(run()).isEmpty();
            assertLogged("advertises no scope beyond the granted \"read\" other than OpenID Connect scopes");
        }

        @Test
        void unknownGrantedScopesAreNotProbed() {
            consent.withScannerClient(Optional.of(new ScannerClient(URI.create(SignedInServer.ORIGIN),
                    SignedInServer.SCANNER_ID, RegisteredClientName.of(SCANNER_NAME),
                    SCANNER_REDIRECT, Set.of(), Optional.of("burp-mcp"))));

            run();

            assertLogged("the scope upgrade probe of the signed-in consent test for " + MCP
                    + " (prerequisite missing: the scanner client's granted scopes are unknown)");
            assertThat(server.requestedScopes(SignedInServer.SCANNER_ID)).isEmpty();
        }
    }

    @Nested
    class ScannerClientOfAnotherIssuer {

        private final URI otherIssuer = URI.create("https://other-as.example.com");

        @BeforeEach
        void signedInAtAnotherAuthorizationServerThatWouldRememberEveryKey() {
            consent.withScannerClient(Optional.of(FakeSignedInConsent.scannerClient(SignedInServer.SCANNER_ID,
                    otherIssuer)));
            server.rememberWhen((client, scopes) -> client.id().equals(SignedInServer.SCANNER_ID)
                    || client.name().equals(SCANNER_NAME)
                    || client.redirect().getHost().equals(SCANNER_REDIRECT.getHost()));
        }

        @Test
        void reportsNoKeyedOrScopeFinding() {
            assertThat(run()).isEmpty();
        }

        @Test
        void registersOnlyTheFreshControlClient() {
            run();

            assertThat(server.registrations()).hasSize(1);
            assertThat(server.requestedScopes(SignedInServer.SCANNER_ID)).isEmpty();
        }

        @Test
        void logsWhyNamingBothIssuers() {
            run();

            Stream.of("same client name", "same redirect host", "same client_id prefix", "scope upgrade").forEach(probe ->
                    assertLogged("the " + probe + " probe of the signed-in consent test for " + MCP
                            + " (prerequisite missing: the scanner's own OAuth client was issued by " + otherIssuer
                            + ", not by " + SignedInServer.ORIGIN + ", the authorization server under test)"));
        }
    }

    @Nested
    class RequestedScope {

        @BeforeEach
        void protectTheResourceWithEveryScope() {
            server.protectResourceWithScopes("[\"read\",\"write\",\"admin\"]");
        }

        @Test
        void everyRegistrationProbeAsksForExactlyTheScannerClientsGrantedScope() {
            run();

            assertThat(server.registeredIds()).hasSize(3).allSatisfy(clientId ->
                    assertThat(server.requestedScopes(clientId)).containsExactly("read"));
        }

        @Test
        void withoutTheScannerClientTheFreshClientProbeAsksForTheServerScope() {
            consent.withScannerClient(Optional.empty());

            run();

            assertThat(server.registeredIds()).singleElement().satisfies(clientId ->
                    assertThat(server.requestedScopes(clientId)).containsExactly("read write admin"));
        }

        @Test
        void consentRememberedByNameButReAskedForWiderScopeStillFires() {
            server.rememberWhen((client, scopes) -> SignedInServer.GRANTED.containsAll(scopes)
                    && client.name().equals(SCANNER_NAME));

            assertThat(names(run())).containsExactly(BY_NAME);
        }
    }

    @Nested
    class FreshClientControl {

        @Test
        void anInteractionRequiredErrorAtTheCallbackCountsAsConsentShown() {
            server.promptWith((client, request) -> ScriptedHttp.redirect(client.redirect()
                    + "?error=interaction_required&state=" + ScriptedHttp.queryParameter(request, "state")));

            run();

            assertThat(server.registrations()).hasSize(3);
        }

        @Test
        void anInconclusiveControlSkipsTheKeyedProbesButNotTheScopeUpgrade() {
            server.promptWith((client, request) -> ScriptedHttp.json(500, "{\"error\":\"server_error\"}"));

            run();

            assertThat(server.registrations()).hasSize(1);
            Stream.of("same client name", "same redirect host", "same client_id prefix").forEach(probe ->
                    assertLogged("the " + probe + " probe of the signed-in consent test for " + MCP
                            + " (not applicable: the fresh-client control was inconclusive: the authorization "
                            + "walk ended on HTTP 500 application/json)"));
            assertThat(server.requestedScopes(SignedInServer.SCANNER_ID)).containsExactly("read", "read write admin");
        }
    }

    @Nested
    class ProbesNotRun {

        @Test
        void optedOutSendsNoRequestOfItsOwn() {
            HttpRequestResponse base = base();
            assertThat(check(SignedInConsent.OPTED_OUT).trials().get(1).whyNotApplicable(base))
                    .map(SkipReason::detail)
                    .contains("the opt-in setting 'Test OAuth consent with my sign-in' is off");

            new HostAudits(check(SignedInConsent.OPTED_OUT)).audit(base, server.http().http());
            int withTrial = server.http().sent().size();
            SignedInServer anonymousOnly = new SignedInServer();
            check(SignedInConsent.OPTED_OUT).audit(base, anonymousOnly.http().http());

            assertThat(withTrial).isEqualTo(anonymousOnly.http().sent().size());
        }

        @Test
        void noAuthorizationServerWithARegistrationEndpoint() {
            server.withoutRegistration();

            assertThat(run()).isEmpty();
            assertLogged("no authorization server with a registration endpoint discovered");
        }

        @Test
        void aRefusedRegistrationStillLeavesTheScopeUpgradeProbe() {
            server.http().on("POST", SignedInServer.REGISTER, ScriptedResponses.UNAUTHORIZED);
            server.rememberWhen((client, scopes) -> client.id().equals(SignedInServer.SCANNER_ID));

            assertThat(names(run())).containsExactly(BROADER_SCOPE);
            assertLogged("the fresh client probe of the signed-in consent test for " + MCP
                    + " (prerequisite missing: dynamic client registration did not issue a client_id)");
        }

        @Test
        void noSessionAndNoBrowserObservation() {
            consent.withoutSession();

            assertThat(run()).isEmpty();
            assertLogged("no signed-in session for as.example.com: sign in through Burp's browser or with OAuth "
                    + "at Connect");
            assertThat(server.registrations()).isEmpty();
        }

        @Test
        void withoutTheScannerClientOnlyTheFreshNameProbeRuns() {
            consent.withScannerClient(Optional.empty());

            run();

            assertThat(server.registrations()).hasSize(1);
            Stream.of("same client name", "same redirect host", "same client_id prefix", "scope upgrade").forEach(probe ->
                    assertLogged("the " + probe + " probe of the signed-in consent test for " + MCP
                            + " (prerequisite missing: the scanner's own OAuth client is unknown: connect with OAuth)"));
        }

        @Test
        void aPreRegisteredScannerClientWhoseNameIsUnknownGetsNoSameNameProbe() {
            consent.withScannerClient(Optional.of(new ScannerClient(URI.create(SignedInServer.ORIGIN),
                    SignedInServer.SCANNER_ID, RegisteredClientName.unknown(), SCANNER_REDIRECT, SignedInServer.GRANTED,
                    Optional.of("burp-mcp"))));

            run();

            assertThat(server.registrations()).noneSatisfy(registration -> assertThat(registration.bodyToString())
                    .contains("\"client_name\":\"" + SCANNER_NAME + "\""));
            assertLogged("the same client name probe of the signed-in consent test for " + MCP + " (prerequisite missing: "
                    + RegisteredClientName.UNKNOWN + ")");
        }

        @Test
        void aScannerClientIdWithoutAStructuredPrefix() {
            run();

            assertLogged("the scanner's client_id scanner-client has no structured prefix");
        }

        @Test
        void aPrefixEveryNewClientSharesIsLeftToTheFreshClientProbe() {
            consent.withScannerClient(Optional.of(FakeSignedInConsent.scannerClient(PREFIXED_SCANNER_ID)));
            server.mintClientIds(client -> "burp-mcp_" + UUID.randomUUID().toString().substring(0, 8) + "z9");

            run();

            assertLogged("every new client_id starts with burp-mcp, which the fresh client probe already covers");
            assertThat(server.registrations()).hasSize(3);
        }

        @Test
        void anIssuedClientIdWithoutTheScannerPrefix() {
            consent.withScannerClient(Optional.of(FakeSignedInConsent.scannerClient(PREFIXED_SCANNER_ID)));

            run();

            assertLogged("without the scanner's prefix burp-mcp, even for software_id burp-mcp");
            assertThat(server.registrations()).hasSize(4);
            assertThat(server.deletedClients()).hasSize(4);
        }

        @Test
        void noScopeBeyondTheGrantedOnes() {
            server.advertiseScopes("[\"read\"]");

            run();

            assertLogged("the authorization server advertises no scope beyond the granted \"read\"");
        }

        @Test
        void aScannerClientWhoseConsentIsNotRemembered() {
            server.rememberWhen((client, scopes) -> false);

            run();

            assertLogged("so the consent is not remembered");
            assertThat(server.http().sentTo(AUTHORIZE)).hasSize(4);
        }
    }

    @Nested
    class BrowserObservations {

        private BrowserConsentObservation observation(SignedInProbe probe, boolean codeArrived) {
            return new BrowserConsentObservation(probe, URI.create(AUTHORIZE), "probe " + probe,
                    URI.create("http://127.0.0.1:49151/cb"),
                    codeArrived ? Optional.of(Duration.ofMillis(420)) : Optional.empty());
        }

        @BeforeEach
        void withoutCookies() {
            consent.withoutSession();
        }

        @Test
        void eachCodeWithoutInteractionIsTentativeWithoutEvidence() {
            consent.observed(observation(SignedInProbe.SAME_NAME, true))
                    .observed(observation(SignedInProbe.FRESH_NAME, false))
                    .observed(observation(SignedInProbe.SAME_REDIRECT_HOST, false))
                    .observed(observation(SignedInProbe.SCOPE_UPGRADE, true));

            List<AuditIssue> issues = run();

            assertThat(names(issues)).containsExactly(BY_NAME, BROADER_SCOPE);
            assertThat(issues).allSatisfy(issue -> {
                assertThat(issue.confidence()).isEqualTo(AuditIssueConfidence.TENTATIVE);
                assertThat(issue.requestResponses()).isEmpty();
                assertThat(issue.detail()).contains("420 ms");
            });
            assertThat(server.registrations()).isEmpty();
        }

        @Test
        void aCodeThatCameTooLateToRuleOutAnApprovalClickIsNotReported() {
            consent.observed(new BrowserConsentObservation(SignedInProbe.SAME_NAME, URI.create(AUTHORIZE),
                    "probe", URI.create("http://localhost:49151/cb"), Optional.of(Duration.ofMillis(3_000))));

            assertThat(run()).isEmpty();
        }

        @Test
        void aSameNameCodeWithoutTheFreshNameControlIsReportedAsTheGeneralFinding() {
            consent.observed(observation(SignedInProbe.SAME_NAME, true));

            List<AuditIssue> issues = run();

            assertThat(names(issues)).containsExactly(ANY_CLIENT);
            assertThat(issues.get(0).confidence()).isEqualTo(AuditIssueConfidence.TENTATIVE);
            assertThat(issues.get(0).detail()).contains("reused the client_name")
                    .contains("fresh-name control was not tried or its client was not registered")
                    .doesNotContain("unfamiliar name");
        }

        @Test
        void aSameNameCodeWhoseFreshNameControlAnsweredTooLateIsReportedAsTheGeneralFinding() {
            consent.observed(observation(SignedInProbe.SAME_NAME, true))
                    .observed(new BrowserConsentObservation(SignedInProbe.FRESH_NAME, URI.create(AUTHORIZE),
                            "fresh probe", URI.create("http://[::1]:49151/cb"), Optional.of(Duration.ofMillis(3_000))));

            List<AuditIssue> issues = run();

            assertThat(names(issues)).containsExactly(ANY_CLIENT);
            assertThat(issues.get(0).detail()).contains("fresh-name control received a code after 3000 ms");
        }

        @Test
        void theLatestFreshNameControlDecidesTheLabel() {
            consent.observed(observation(SignedInProbe.FRESH_NAME, false))
                    .observed(observation(SignedInProbe.SAME_NAME, true))
                    .observed(new BrowserConsentObservation(SignedInProbe.FRESH_NAME, URI.create(AUTHORIZE),
                            "fresh probe", URI.create("http://[::1]:49151/cb"), Optional.of(Duration.ofMillis(3_000))));

            assertThat(names(run())).containsExactly(ANY_CLIENT);
        }

        @Test
        void aSameNameCodeWhoseFreshNameControlMetConsentIsRememberedByName() {
            consent.observed(observation(SignedInProbe.SAME_NAME, true))
                    .observed(observation(SignedInProbe.FRESH_NAME, false));

            assertThat(names(run())).containsExactly(BY_NAME);
        }

        @Test
        void aFreshClientCodeSubsumesTheOthers() {
            consent.observed(observation(SignedInProbe.SAME_NAME, true))
                    .observed(observation(SignedInProbe.FRESH_NAME, true));

            assertThat(names(run())).containsExactly(ANY_CLIENT);
        }
    }

    @Nested
    class CookieScheme {

        private static final String PLAIN_HTTP_AUTHORIZE = "http://as.example.com/authorize";
        private static final String LOOPBACK_ISSUER = "http://127.0.0.1:9000";
        private static final String LOOPBACK_AUTHORIZE = LOOPBACK_ISSUER + "/authorize";

        @Test
        void aPlainHttpAuthorizationEndpointNeverGetsTheCookieJarSession() {
            server.advertiseAuthorizationEndpoint(PLAIN_HTTP_AUTHORIZE);

            run();

            assertThat(consent.cookieSessionsAskedFor()).isEmpty();
            assertThat(server.registrations()).isEmpty();
            assertThat(server.http().sent()).noneSatisfy(request ->
                    assertThat(request.headerValue("Cookie")).isNotNull());
            assertLogged("Burp's cookie jar cannot tell Secure cookies apart, so its cookies are not sent to the "
                    + "plain-http authorization endpoint " + PLAIN_HTTP_AUTHORIZE);
        }

        @Test
        void aPlainHttpAuthorizationEndpointFallsBackToBrowserObservations() {
            server.advertiseAuthorizationEndpoint(PLAIN_HTTP_AUTHORIZE);
            consent.observed(new BrowserConsentObservation(SignedInProbe.SAME_NAME, URI.create(PLAIN_HTTP_AUTHORIZE),
                    "probe", URI.create("http://127.0.0.1:49151/cb"), Optional.of(Duration.ofMillis(300))));
            consent.observed(new BrowserConsentObservation(SignedInProbe.FRESH_NAME, URI.create(PLAIN_HTTP_AUTHORIZE),
                    "fresh probe", URI.create("http://127.0.0.1:49151/cb"), Optional.empty()));

            assertThat(names(run())).containsExactly(BY_NAME);
        }

        @Test
        void aLoopbackHttpAuthorizationEndpointUsesTheCookieJarSession() {
            server.delegateToIssuer(LOOPBACK_ISSUER);

            run();

            assertThat(consent.cookieSessionsAskedFor()).containsExactly(URI.create(LOOPBACK_AUTHORIZE));
        }

        @Test
        void anHttpsAuthorizationEndpointUsesTheCookieJarSession() {
            run();

            assertThat(consent.cookieSessionsAskedFor()).containsExactly(URI.create(AUTHORIZE));
        }
    }

    @Nested
    class EndpointsOutsideTheIssuerOrigin {

        private static final String ATTACKER = "https://attacker.example.net";

        @BeforeEach
        void advertiseAttackerTokenAndRegistrationEndpoints() {
            server.advertiseRegistrationAndTokenAt(ATTACKER);
        }

        @Test
        void neverUsesTheCookieJarSessionNorSendsAnythingToTheForeignOrigin() {
            run();

            assertThat(consent.cookieSessionsAskedFor()).isEmpty();
            assertThat(server.http().sent()).noneSatisfy(request ->
                    assertThat(request.headerValue("Cookie")).isNotNull());
            assertThat(server.http().sentUrls()).noneSatisfy(url -> assertThat(url).startsWith(ATTACKER));
            assertLogged("the signed-in consent test on");
            assertLogged("the authorization server's registration endpoint " + ATTACKER + "/register is not on the "
                    + "origin of its issuer " + SignedInServer.ORIGIN);
        }

        @Test
        void aResourceOffTheMcpEndpointsOriginNeverGetsATokenFromTheSession() {
            server.advertiseRegistrationAndTokenAt(SignedInServer.ORIGIN).protectResourceNamed(ATTACKER + "/api");

            run();

            assertThat(consent.cookieSessionsAskedFor()).isEmpty();
            assertThat(server.http().sent()).noneSatisfy(request ->
                    assertThat(request.headerValue("Cookie")).isNotNull());
            assertLogged("the protected resource " + ATTACKER + "/api is not on the origin of the MCP endpoint "
                    + SignedInServer.ORIGIN);
        }

        @Test
        void aSplitOriginWithoutBrowserObservationsLogsOnlyTheSplit() {
            consent.withoutSession();

            run();

            assertThat(logged()).noneSatisfy(line -> assertThat(line).contains("no signed-in session for"));
        }

        @Test
        void stillReportsTheBrowserObservations() {
            consent.withoutSession().observed(new BrowserConsentObservation(SignedInProbe.FRESH_NAME,
                    URI.create(AUTHORIZE), "probe", URI.create("http://localhost:49151/cb"),
                    Optional.of(Duration.ofMillis(300))));

            assertThat(names(run())).containsExactly(ANY_CLIENT);
        }
    }

    private static final class ScriptedResponses {

        static final String UNAUTHORIZED = "HTTP/1.1 401 Unauthorized\r\nWWW-Authenticate: Bearer\r\n\r\n";
    }
}
