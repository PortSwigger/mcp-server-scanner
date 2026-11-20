package com.mcpscanner.checks.catalog.oauthauthorizationconsent;

import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.scanner.audit.issues.AuditIssue;
import burp.api.montoya.scanner.audit.issues.AuditIssueConfidence;
import burp.api.montoya.scanner.audit.issues.AuditIssueSeverity;
import com.mcpscanner.auth.BearerTokenAuthStrategy;
import com.mcpscanner.checks.api.CheckKind;
import com.mcpscanner.checks.shared.oauth.ScriptedHttp;
import com.mcpscanner.logging.McpEventLog;
import com.mcpscanner.testutil.MontoyaTestFactory;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import java.util.List;

import static com.mcpscanner.checks.catalog.oauthauthorizationconsent.ConsentServer.AUTHORIZE;
import static com.mcpscanner.checks.catalog.oauthauthorizationconsent.ConsentServer.CLIENT_URI;
import static com.mcpscanner.checks.catalog.oauthauthorizationconsent.ConsentServer.MCP;
import static com.mcpscanner.checks.catalog.oauthauthorizationconsent.ConsentServer.ORIGIN;
import static com.mcpscanner.checks.shared.oauth.ScriptedHttp.html;
import static com.mcpscanner.checks.shared.oauth.ScriptedHttp.json;
import static com.mcpscanner.checks.shared.oauth.ScriptedHttp.queryParameter;
import static com.mcpscanner.checks.shared.oauth.ScriptedHttp.redirect;
import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.argThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;

class OAuthAuthorizationConsentCheckTest {

    private static final String AUTHORIZATION_ISSUE = "MCP OAuth authorization without login or consent";
    private static final String REUSE_ISSUE = "MCP OAuth authorization code redeemed more than once";
    private static final String TOOLS_LIST = "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/list\"}";

    private final McpEventLog eventLog = mock(McpEventLog.class);
    private final OAuthAuthorizationConsentCheck check = new OAuthAuthorizationConsentCheck(eventLog,
            () -> new BearerTokenAuthStrategy("scanner-token"));
    private ConsentServer server;

    @BeforeEach
    void setUp() {
        MontoyaTestFactory.install();
        server = new ConsentServer();
    }

    private static HttpRequestResponse base(String method, String body) {
        HttpRequest request = HttpRequest.httpRequestFromUrl(MCP).withMethod(method).withBody(body)
                .withAddedHeader("Content-Type", "application/json")
                .withAddedHeader("Authorization", "Bearer scanner-token")
                .withAddedHeader("Cookie", "sid=scanner")
                .withAddedHeader("Mcp-Session-Id", ConsentServer.SCANNER_SESSION);
        return HttpRequestResponse.httpRequestResponse(request, null);
    }

    private List<AuditIssue> audit() {
        return check.audit(base("POST", TOOLS_LIST), server.http().http());
    }

    private AuditIssue single(List<AuditIssue> issues, String name) {
        return issues.stream().filter(issue -> issue.name().equals(name)).findFirst().orElseThrow();
    }

    private static List<String> evidence(AuditIssue issue) {
        return issue.requestResponses().stream().map(OAuthAuthorizationConsentCheckTest::exchange).toList();
    }

    private static String exchange(HttpRequestResponse exchange) {
        HttpRequest request = exchange.request();
        String endpoint = request.method() + " " + request.url().replaceAll("\\?.*", "");
        if (request.url().equals(ConsentServer.TOKEN)) {
            return endpoint + " " + request.bodyToString().replaceAll(".*\\bcode=([^&]*).*", "$1");
        }
        if (request.url().equals(MCP)) {
            return endpoint + " " + (request.hasHeader("Authorization") ? request.headerValue("Authorization")
                    : "anonymous");
        }
        return endpoint;
    }

    @Test
    void describesAHostCheckWithItsCatalogId() {
        assertThat(check.descriptor()).isSameAs(OAuthAuthorizationConsentDescriptor.DESCRIPTOR);
        assertThat(check.descriptor().id()).isEqualTo("oauth-authorization-consent");
        assertThat(check.descriptor().kind()).isEqualTo(CheckKind.HOST);
    }

    @Test
    void appliesOnlyToAnMcpJsonRpcRequest() {
        assertThat(check.appliesTo(base("POST", TOOLS_LIST))).isTrue();
        assertThat(check.appliesTo(base("POST", "{\"hello\":\"world\"}"))).isFalse();
    }

    @Nested
    class UnattendedAuthorization {

        @Test
        void aCodeThatRedeemsToATokenOpeningARefusedEndpointIsHighAndCertain() {
            AuditIssue issue = single(audit(), AUTHORIZATION_ISSUE);

            assertThat(issue.severity()).isEqualTo(AuditIssueSeverity.HIGH);
            assertThat(issue.confidence()).isEqualTo(AuditIssueConfidence.CERTAIN);
            assertThat(issue.detail()).contains("HTTP 401");
        }

        @Test
        void aServerThatRequiresAnMcpSessionIsJudgedInAFreshSessionPerCredential() {
            server.requireSessions();

            AuditIssue issue = single(audit(), AUTHORIZATION_ISSUE);

            assertThat(issue.severity()).isEqualTo(AuditIssueSeverity.HIGH);
            assertThat(server.http().sentTo(MCP)).anySatisfy(request ->
                    assertThat(request.headerValue("Mcp-Session-Id")).startsWith("session-"));
            assertThat(server.http().sentTo(MCP))
                    .filteredOn(request -> request.bodyToString().contains("\"method\":\"initialize\""))
                    .hasSize(2)
                    .allSatisfy(initialize -> assertThat(initialize.headerValue("Authorization"))
                            .isNotEqualTo(ConsentServer.SCANNER_CREDENTIAL));
        }

        @Test
        void aWorkingTokenAttachesTheTrailTheRedemptionAndBothToolsListCalls() {
            assertThat(evidence(single(audit(), AUTHORIZATION_ISSUE))).containsExactly(
                    "GET " + AUTHORIZE, "POST " + ConsentServer.TOKEN + " code-1", "POST " + MCP + " anonymous",
                    "POST " + MCP + " Bearer token-code-1-1");
        }

        @Test
        void aCodeThatDoesNotRedeemAttachesOnlyTheTrail() {
            server.route("POST", ConsentServer.TOKEN, request -> json(400, "{\"error\":\"invalid_client\"}"));

            assertThat(evidence(single(audit(), AUTHORIZATION_ISSUE))).containsExactly("GET " + AUTHORIZE);
        }

        @Test
        void aTokenThatDoesNotOpenTheEndpointAttachesOnlyTheTrail() {
            server.rejectIssuedTokens();

            assertThat(evidence(single(audit(), AUTHORIZATION_ISSUE))).containsExactly("GET " + AUTHORIZE);
        }

        @Test
        void aCodeIssuedToAnAnonymousSessionAttachesOnlyTheTrail() {
            server.signInAnonymousVisitors();

            assertThat(evidence(single(audit(), AUTHORIZATION_ISSUE))).containsExactly(
                    "GET " + AUTHORIZE, "GET " + ORIGIN + "/login", "GET " + AUTHORIZE);
        }

        @Test
        void anAlreadyOpenEndpointAttachesTheTrailTheRedemptionAndTheAnonymousCall() {
            server.openEndpoint();

            assertThat(evidence(single(audit(), AUTHORIZATION_ISSUE))).containsExactly(
                    "GET " + AUTHORIZE, "POST " + ConsentServer.TOKEN + " code-1", "POST " + MCP + " anonymous");
        }

        @Test
        void aCodeThatDoesNotRedeemIsMediumAndFirm() {
            server.route("POST", ConsentServer.TOKEN, request -> json(400, "{\"error\":\"invalid_client\"}"));

            AuditIssue issue = single(audit(), AUTHORIZATION_ISSUE);

            assertThat(issue.severity()).isEqualTo(AuditIssueSeverity.MEDIUM);
            assertThat(issue.confidence()).isEqualTo(AuditIssueConfidence.FIRM);
        }

        @Test
        void aTokenThatDoesNotOpenTheEndpointLeavesTheFindingMedium() {
            server.rejectIssuedTokens();

            assertThat(single(audit(), AUTHORIZATION_ISSUE).severity()).isEqualTo(AuditIssueSeverity.MEDIUM);
        }

        @Test
        void anEndpointThatAnswersWithoutAnyTokenMakesTheFindingInformational() {
            server.openEndpoint();

            assertThat(single(audit(), AUTHORIZATION_ISSUE).severity()).isEqualTo(AuditIssueSeverity.INFORMATION);
        }

        @Test
        void aLoginPageIsSilent() {
            server.authorizeWith(request -> html("<form><input name=password></form>"));

            assertThat(audit()).isEmpty();
        }

        @Test
        void aCallbackWithAnotherStateIsSilent() {
            server.authorizeWith(request -> redirect(queryParameter(request, "redirect_uri") + "?code=code-1&state=x"));

            assertThat(audit()).isEmpty();
        }

        @Test
        void aCodeIssuedOnlyAfterTheServerCreatedASessionIsMediumAndTentative() {
            server.signInAnonymousVisitors();

            AuditIssue issue = single(audit(), AUTHORIZATION_ISSUE);

            assertThat(issue.severity()).isEqualTo(AuditIssueSeverity.MEDIUM);
            assertThat(issue.confidence()).isEqualTo(AuditIssueConfidence.TENTATIVE);
            assertThat(issue.detail()).contains("session").contains(ORIGIN + "/login");
        }

        @Test
        void aSessionCreatedForTheVisitorKeepsAnUnusableTokenTentative() {
            server.signInAnonymousVisitors().rejectIssuedTokens();

            AuditIssue issue = single(audit(), AUTHORIZATION_ISSUE);

            assertThat(issue.severity()).isEqualTo(AuditIssueSeverity.MEDIUM);
            assertThat(issue.confidence()).isEqualTo(AuditIssueConfidence.TENTATIVE);
        }

        @Test
        void anAnonymousFailureThatIsNotAnAuthenticationRefusalNeverMakesTheFindingHigh() {
            server.failAnonymousRequestsWithoutAnAuthenticationChallenge().redeemEveryCodeUpTo(2);

            List<AuditIssue> issues = audit();

            assertThat(issues).extracting(AuditIssue::name).containsExactly(AUTHORIZATION_ISSUE);
            assertThat(issues.get(0).severity()).isEqualTo(AuditIssueSeverity.MEDIUM);
            assertThat(issues.get(0).confidence()).isEqualTo(AuditIssueConfidence.FIRM);
        }

        @Test
        void withoutATokenEndpointTheCodeIsReportedMediumAndFirm() {
            server.route("GET", ORIGIN + "/.well-known/oauth-authorization-server", request -> json(200,
                    "{\"issuer\":\"" + ORIGIN + "\",\"authorization_endpoint\":\"" + AUTHORIZE + "\","
                            + "\"registration_endpoint\":\"" + ConsentServer.REGISTER + "\"}"));

            AuditIssue issue = single(audit(), AUTHORIZATION_ISSUE);

            assertThat(issue.severity()).isEqualTo(AuditIssueSeverity.MEDIUM);
            assertThat(issue.confidence()).isEqualTo(AuditIssueConfidence.FIRM);
            assertThat(issue.detail()).contains("advertises no token endpoint");
            assertThat(evidence(issue)).containsExactly("GET " + AUTHORIZE);
        }

        @Test
        void neverJudgesATokenInTheScannersOwnSession() {
            audit();

            assertThat(server.http().sentTo(MCP)).noneSatisfy(request ->
                    assertThat(request.headerValue("Mcp-Session-Id")).isEqualTo(ConsentServer.SCANNER_SESSION));
        }

        @Test
        void neverSendsTheScannerCredentialsToTheAuthorizationEndpoint() {
            audit();

            assertThat(server.authorizationRequests()).isNotEmpty().allSatisfy(request -> {
                assertThat(request.hasHeader("Authorization")).isFalse();
                assertThat(request.hasHeader("Cookie")).isFalse();
            });
        }

        @Test
        void stopsFollowingRedirectsAfterTheHopLimit() {
            server.authorizeWith(request -> redirect(AUTHORIZE + "?again=1"));

            assertThat(audit()).isEmpty();
            assertThat(server.authorizationRequests()).hasSize(6);
        }

        @Test
        void registersAPublicClientForTheCodeGrantOnly() {
            audit();

            assertThat(server.http().sentTo(ConsentServer.REGISTER)).singleElement().satisfies(request ->
                    assertThat(request.bodyToString()).contains("\"grant_types\":[\"authorization_code\"]"));
        }

        @Test
        void addsTheRefreshGrantOnlyWhenTheServerRequiresIt() {
            server.requireRefreshGrantAtRegistration();

            assertThat(single(audit(), AUTHORIZATION_ISSUE).severity()).isEqualTo(AuditIssueSeverity.HIGH);
            assertThat(server.http().sentTo(ConsentServer.REGISTER)).hasSize(2);
        }

        @Test
        void neverFollowsAnUpstreamAuthorizationRedirect() {
            server.authorizeWith(request -> redirect("https://idp.example.org/authorize?response_type=code"
                    + "&client_id=proxy-static&redirect_uri=" + ORIGIN + "%2Fauth%2Fcallback&state=txn-1"));

            assertThat(audit()).isEmpty();
            assertThat(server.http().sentUrls()).noneMatch(url -> url.startsWith("https://idp.example.org"));
        }

        @Test
        void neverFollowsARedirectToAnotherOrigin() {
            server.authorizeWith(request -> redirect("https://login.example.org/signin"));

            assertThat(audit()).isEmpty();
            assertThat(server.http().sentUrls()).noneMatch(url -> url.startsWith("https://login.example.org"));
        }
    }

    @Nested
    class ConfidentialClients {

        private static final String BASIC = "Basic " + java.util.Base64.getEncoder()
                .encodeToString((ConsentServer.CLIENT_ID + ":" + ConsentServer.CLIENT_SECRET)
                        .getBytes(java.nio.charset.StandardCharsets.UTF_8));

        @Test
        void aSecretIssuedDespiteThePublicRegistrationRedeemsCodesInTheForm() {
            server.issueConfidentialClients("none", request -> request.bodyToString()
                    .contains("client_secret=" + ConsentServer.CLIENT_SECRET)).redeemLaterCodesUpTo(2);

            List<AuditIssue> issues = audit();

            assertThat(single(issues, AUTHORIZATION_ISSUE).severity()).isEqualTo(AuditIssueSeverity.HIGH);
            assertThat(issues).extracting(AuditIssue::name).contains(REUSE_ISSUE);
        }

        @Test
        void revokesTheTokensOfAConfidentialClientWithItsSecret() {
            server.issueConfidentialClients("none", request -> request.bodyToString()
                    .contains("client_secret=" + ConsentServer.CLIENT_SECRET));

            audit();

            assertThat(server.http().sentTo(ConsentServer.REVOKE)).isNotEmpty().allSatisfy(request ->
                    assertThat(request.bodyToString()).contains("client_secret=" + ConsentServer.CLIENT_SECRET));
        }

        @Test
        void aSecretIssuedForBasicAuthenticationRedeemsCodesWithTheAuthorizationHeaderOnly() {
            server.issueConfidentialClients("client_secret_basic", request -> BASIC.equals(
                    request.headerValue("Authorization")) && !request.bodyToString().contains("client_id="));

            assertThat(single(audit(), AUTHORIZATION_ISSUE).severity()).isEqualTo(AuditIssueSeverity.HIGH);
        }
    }

    @Nested
    class CodeReuse {

        @Test
        void aCodeThatRedeemsAgainInSequenceIsReported() {
            server.redeemEveryCodeUpTo(2);

            AuditIssue issue = single(audit(), REUSE_ISSUE);

            assertThat(issue.detail()).contains("sequential");
            assertThat(issue.severity()).isEqualTo(AuditIssueSeverity.MEDIUM);
            assertThat(issue.confidence()).isEqualTo(AuditIssueConfidence.CERTAIN);
        }

        @Test
        void aSequentialReuseAttachesBothRedemptionsOfTheCodeAndTheReplayedTokensToolsListCalls() {
            server.redeemEveryCodeUpTo(2);

            assertThat(evidence(single(audit(), REUSE_ISSUE))).containsExactly(
                    "POST " + ConsentServer.TOKEN + " code-1", "POST " + ConsentServer.TOKEN + " code-1",
                    "POST " + MCP + " anonymous", "POST " + MCP + " Bearer token-code-1-2");
        }

        @Test
        void aReplayAnsweredWithTheSameTokenIsWordedAsTheSameToken() {
            server.redeemEveryCodeUpTo(2).cacheTokenResponses();

            assertThat(single(audit(), REUSE_ISSUE).detail()).contains("the same access token");
        }

        @Test
        void aSequentialReplayWhoseTokenDoesNotWorkIsNotReported() {
            server.redeemEveryCodeUpTo(2).honourOnlyTheFirstTokenPerCode();

            assertThat(audit()).extracting(AuditIssue::name).containsExactly(AUTHORIZATION_ISSUE);
            assertThat(server.redemptionsOf("code-1")).isEqualTo(2);
        }

        @Test
        void concurrentRedemptionsWithOnlyOneWorkingTokenAreNotReported() {
            server.redeemLaterCodesUpTo(2).honourOnlyTheFirstTokenPerCode();

            assertThat(audit()).extracting(AuditIssue::name).containsExactly(AUTHORIZATION_ISSUE);
            assertThat(server.redemptionsOf("code-2")).isEqualTo(CodeReuseProbe.CONCURRENT_REDEMPTIONS);
        }

        @Test
        void aCodeThatRedeemsTwiceOnlyUnderConcurrencyIsReported() {
            server.redeemLaterCodesUpTo(2).requireLaterRedemptionsToOverlap(CodeReuseProbe.CONCURRENT_REDEMPTIONS);

            AuditIssue issue = single(audit(), REUSE_ISSUE);

            assertThat(issue.detail()).contains("concurrent");
            assertThat(server.redemptionsOf("code-2")).isEqualTo(CodeReuseProbe.CONCURRENT_REDEMPTIONS);
        }

        @Test
        void reuseIsJudgedOnAServerThatRequiresAnMcpSession() {
            server.requireSessions().redeemEveryCodeUpTo(2);

            assertThat(single(audit(), REUSE_ISSUE).detail()).contains("sequential");
        }

        @Test
        void singleUseCodesAreNotReported() {
            assertThat(audit()).extracting(AuditIssue::name).containsExactly(AUTHORIZATION_ISSUE);
        }

        @Test
        void reuseIsNotProbedWhenTheFirstTokenDoesNotOpenTheEndpoint() {
            server.redeemEveryCodeUpTo(2).rejectIssuedTokens();

            assertThat(audit()).extracting(AuditIssue::name).containsExactly(AUTHORIZATION_ISSUE);
            assertThat(server.redemptionsOf("code-1")).isEqualTo(1);
        }
    }

    @Nested
    class Housekeeping {

        @Test
        void deletesTheProbeClientAfterTheAudit() {
            audit();

            assertThat(server.http().sentTo(CLIENT_URI)).singleElement()
                    .satisfies(request -> assertThat(request.method()).isEqualTo("DELETE"));
        }

        @Test
        void revokesEveryAccessAndRefreshTokenItObtained() {
            server.redeemEveryCodeUpTo(2);

            audit();

            assertThat(server.http().sentTo(ConsentServer.REVOKE)).extracting(request -> request.bodyToString())
                    .containsExactlyInAnyOrder(
                            "token=token-code-1-1&token_type_hint=access_token&client_id=probe-client",
                            "token=refresh-token-code-1-1&token_type_hint=refresh_token&client_id=probe-client",
                            "token=token-code-1-2&token_type_hint=access_token&client_id=probe-client",
                            "token=refresh-token-code-1-2&token_type_hint=refresh_token&client_id=probe-client");
        }

        @Test
        void logsTheTokensItCannotRevoke() {
            server.route("GET", ORIGIN + "/.well-known/oauth-authorization-server", request -> json(200,
                    "{\"issuer\":\"" + ORIGIN + "\",\"authorization_endpoint\":\"" + AUTHORIZE + "\","
                            + "\"registration_endpoint\":\"" + ConsentServer.REGISTER + "\","
                            + "\"token_endpoint\":\"" + ConsentServer.TOKEN + "\"}"));

            audit();

            verify(eventLog).error(argThat(message -> message.contains("no revocation endpoint")
                    && message.contains("client_id probe-client")));
        }

        @Test
        void skipsAServerWithoutARegistrationEndpoint() {
            server.route("GET", ORIGIN + "/.well-known/oauth-authorization-server", request -> json(200,
                    "{\"issuer\":\"" + ORIGIN + "\",\"authorization_endpoint\":\"" + AUTHORIZE + "\"}"));

            assertThat(audit()).isEmpty();
            assertThat(server.authorizationRequests()).isEmpty();
        }
    }

    @Nested
    class SkipLogging {

        private static final String PREFIX = "Scan check: oauth-authorization-consent — ";
        private static final String METADATA = ORIGIN + "/.well-known/oauth-authorization-server";

        @Test
        void aServerWithoutARegistrationEndpointIsSkippedForAMissingPrerequisite() {
            server.route("GET", METADATA, request -> json(200,
                    "{\"issuer\":\"" + ORIGIN + "\",\"authorization_endpoint\":\"" + AUTHORIZE + "\"}"));

            audit();

            verify(eventLog).info(PREFIX + "skipped " + MCP
                    + " (prerequisite missing: no authorization server with a registration endpoint discovered)");
        }

        @Test
        void discoveryCutShortByHttp429IsLoggedAsRateLimited() {
            server.route("GET", METADATA, request -> ScriptedHttp.status(429));

            audit();

            verify(eventLog).info(PREFIX + "stopped " + MCP + " (rate limited: the server answered HTTP 429)");
        }

        @Test
        void discoveryWhoseReplyBurpWithheldIsLoggedAsAStreamedReply() {
            server.route("GET", METADATA, request -> {
                throw new IllegalStateException("Streaming response received");
            });

            audit();

            verify(eventLog).info(PREFIX + "stopped " + MCP + " (streamed reply withheld by Burp: "
                    + "no authorization server with a registration endpoint discovered)");
        }

        @Test
        void aRefusedRegistrationIsSkippedForAMissingPrerequisite() {
            server.route("POST", ConsentServer.REGISTER, request -> json(403, "{\"error\":\"access_denied\"}"));

            audit();

            verify(eventLog).info(PREFIX + "skipped " + MCP
                    + " (prerequisite missing: dynamic client registration did not issue a client_id)");
        }

        @Test
        void anAuthorizationThatIssuesNoCodeSkipsTheRedemptionTests() {
            server.authorizeWith(request -> html("<form><input name=password></form>"));

            audit();

            verify(eventLog).info(PREFIX + "skipped the code redemption and reuse tests for " + MCP
                    + " (not applicable: the authorization endpoint issued no code without login or consent)");
        }

        @Test
        void redirectsBeyondTheHopLimitSkipTheRedemptionTestsForTheBudget() {
            server.authorizeWith(request -> redirect(AUTHORIZE + "?again=1"));

            audit();

            verify(eventLog).info(PREFIX + "stopped the code redemption and reuse tests for " + MCP
                    + " (request budget used up: the authorization redirects exceeded "
                    + UnattendedAuthorizer.MAX_REDIRECTS + " hops)");
        }

        @Test
        void withoutATokenEndpointTheRedemptionTestsAreSkipped() {
            server.route("GET", METADATA, request -> json(200,
                    "{\"issuer\":\"" + ORIGIN + "\",\"authorization_endpoint\":\"" + AUTHORIZE + "\","
                            + "\"registration_endpoint\":\"" + ConsentServer.REGISTER + "\"}"));

            audit();

            verify(eventLog).info(PREFIX + "skipped the code redemption and reuse tests for " + MCP
                    + " (prerequisite missing: the authorization server advertises no token endpoint)");
        }

        @Test
        void aRateLimitAfterTheCodeWasIssuedStopsTheAudit() {
            server.route("POST", ConsentServer.TOKEN, request -> ScriptedHttp.status(429));

            List<AuditIssue> issues = audit();

            assertThat(issues).extracting(AuditIssue::name).containsExactly(AUTHORIZATION_ISSUE);
            verify(eventLog).info(PREFIX + "stopped " + MCP + " (rate limited: the server answered HTTP 429)");
        }

        @Test
        void aCompleteAuditLogsNoSkip() {
            audit();

            verify(eventLog, never()).info(argThat(message -> message.contains("skipped")
                    || message.contains("stopped")));
        }
    }
}
