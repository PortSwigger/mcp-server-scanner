package com.mcpscanner.checks.catalog.oauthrefreshgrant;

import burp.api.montoya.http.Http;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.api.montoya.scanner.audit.issues.AuditIssue;
import burp.api.montoya.scanner.audit.issues.AuditIssueConfidence;
import burp.api.montoya.scanner.audit.issues.AuditIssueSeverity;
import com.mcpscanner.auth.AuthStrategy;
import com.mcpscanner.auth.BearerTokenAuthStrategy;
import com.mcpscanner.auth.OAuthAuthCodeStrategy;
import com.mcpscanner.auth.oauth.TestOAuthStrategies;
import com.mcpscanner.core.oauth.RegistrationMode;
import com.mcpscanner.auth.grant.ClientType;
import com.mcpscanner.auth.oauth.OAuthException;
import com.mcpscanner.auth.oauth.OAuthTokens;
import com.mcpscanner.checks.api.CheckKind;
import com.mcpscanner.http.ScanQueueBypass;
import com.mcpscanner.logging.McpEventLog;
import com.mcpscanner.testutil.MontoyaTestFactory;
import com.nimbusds.oauth2.sdk.token.BearerAccessToken;
import com.nimbusds.oauth2.sdk.token.RefreshToken;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;

import java.net.URI;
import java.time.Clock;
import java.time.Instant;
import java.util.List;

import static com.mcpscanner.checks.catalog.oauthrefreshgrant.ScriptedOAuthMcpServer.CLIENT_ID;
import static com.mcpscanner.checks.catalog.oauthrefreshgrant.ScriptedOAuthMcpServer.CLIENT_SECRET;
import static com.mcpscanner.checks.catalog.oauthrefreshgrant.ScriptedOAuthMcpServer.LIVE_REFRESH_TOKEN;
import static com.mcpscanner.checks.catalog.oauthrefreshgrant.ScriptedOAuthMcpServer.MCP_URL;
import static com.mcpscanner.checks.catalog.oauthrefreshgrant.ScriptedOAuthMcpServer.ORIGIN;
import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.contains;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;

class OAuthRefreshGrantCheckTest {

    private static final String PREFIX = "Scan check: oauth-refresh-grant — ";

    private final McpEventLog eventLog = mock(McpEventLog.class);
    private ScriptedOAuthMcpServer server;

    @BeforeEach
    void setUp() {
        MontoyaTestFactory.install();
        server = new ScriptedOAuthMcpServer();
    }

    @Test
    void descriptorDeclaresAHostCheckWithMediumFirmHeadline() {
        assertThat(OAuthRefreshGrantDescriptor.DESCRIPTOR.id()).isEqualTo("oauth-refresh-grant");
        assertThat(OAuthRefreshGrantDescriptor.DESCRIPTOR.kind()).isEqualTo(CheckKind.HOST);
        assertThat(OAuthRefreshGrantDescriptor.DESCRIPTOR.headlineSeverity()).isEqualTo(AuditIssueSeverity.MEDIUM);
        assertThat(OAuthRefreshGrantDescriptor.DESCRIPTOR.headlineConfidence()).isEqualTo(AuditIssueConfidence.FIRM);
        assertThat(OAuthRefreshGrantDescriptor.DESCRIPTOR.cwes()).extracting(cwe -> cwe.id()).containsExactly(287, 285);
    }

    @Test
    void appliesOnlyToMcpRequestsWhenTheSessionHasARefreshGrant() {
        OAuthRefreshGrantCheck oauth = check(strategy(CLIENT_SECRET, ClientType.CONFIDENTIAL_CONFIGURED));
        OAuthRefreshGrantCheck bearer = check(new BearerTokenAuthStrategy("static"));

        assertThat(oauth.appliesTo(mcpBase())).isTrue();
        assertThat(oauth.appliesTo(nonMcpBase())).isFalse();
        assertThat(bearer.appliesTo(mcpBase())).isFalse();
    }

    @Test
    void reportsAFirmClientAuthenticationIssueWhenTheOmittedSecretIsAccepted() {
        server.acceptsMissingSecret = true;

        List<AuditIssue> issues = audit(strategy(CLIENT_SECRET, ClientType.CONFIDENTIAL_REGISTERED));

        assertThat(issues).singleElement().satisfies(issue -> {
            assertThat(issue.name()).isEqualTo(OAuthRefreshGrantIssues.CLIENT_AUTHENTICATION_ISSUE);
            assertThat(issue.severity()).isEqualTo(AuditIssueSeverity.MEDIUM);
            assertThat(issue.confidence()).isEqualTo(AuditIssueConfidence.FIRM);
            assertThat(issue.detail()).contains("no client secret").doesNotContain("wrong client secret");
        });
    }

    @Test
    void sendsEveryAuthorizationServerRequestOutsideTheScanQueueAndMcpRequestsOnIt() {
        server.acceptsMissingSecret = true;
        Http scanQueue = server.http();
        Http unqueued = server.http();

        check(strategy(CLIENT_SECRET, ClientType.CONFIDENTIAL_REGISTERED))
                .audit(mcpBase(), ScanQueueBypass.through(unqueued).around(scanQueue));

        assertThat(pathsSentThrough(unqueued)).contains("/token").allMatch(path -> !path.equals("/mcp"));
        assertThat(pathsSentThrough(scanQueue)).isNotEmpty().allMatch(path -> path.equals("/mcp"));
    }

    private static List<String> pathsSentThrough(Http http) {
        return Mockito.mockingDetails(http).getInvocations().stream()
                .filter(invocation -> invocation.getMethod().getName().equals("sendRequest"))
                .map(invocation -> URI.create(((HttpRequest) invocation.getArgument(0)).url()).getPath())
                .toList();
    }

    @Test
    void neverCarriesTheBrowserCookieOfTheBaseRequestIntoTokenProbes() {
        server.acceptsMissingSecret = true;
        HttpRequestResponse base = mcpBase();
        HttpRequestResponse withCookie = HttpRequestResponse.httpRequestResponse(
                base.request().withAddedHeader("Cookie", "sid=browser"), base.response());

        check(strategy(CLIENT_SECRET, ClientType.CONFIDENTIAL_REGISTERED)).audit(withCookie, server.http());

        assertThat(server.mcpRequests).isNotEmpty()
                .allSatisfy(request -> assertThat(request.hasHeader("Cookie")).isFalse());
    }

    @Test
    void clientAuthenticationEvidenceIsTheAcceptedRefreshItsToolsListAndTheUnissuedTokenRefusal() {
        server.acceptsMissingSecret = true;

        List<AuditIssue> issues = audit(strategy(CLIENT_SECRET, ClientType.CONFIDENTIAL_REGISTERED));

        assertThat(issues).singleElement().satisfies(issue -> {
            assertThat(issue.requestResponses()).extracting(this::label)
                    .containsExactly("omitted-secret-refresh", "tools/list", "unissued-refresh");
            assertThat(issue.detail()).contains("Attached: the refresh with the client_id only, with no client secret, "
                    + "the MCP tools/list request sent with the access token it issued, and the refused refresh "
                    + "with the unissued refresh token.");
        });
    }

    @Test
    void clientAuthenticationEvidenceAttachesOnlyTheFirstAcceptedRefreshWhenBothAreAccepted() {
        server.acceptsMissingSecret = true;
        server.acceptsWrongSecret = true;

        List<AuditIssue> issues = audit(strategy(CLIENT_SECRET, ClientType.CONFIDENTIAL_REGISTERED));

        assertThat(issues).singleElement().satisfies(issue -> {
            assertThat(issue.requestResponses()).extracting(this::label)
                    .containsExactly("omitted-secret-refresh", "tools/list", "unissued-refresh");
            assertThat(issue.detail()).contains("no client secret").contains("wrong client secret")
                    .contains("Attached: the refresh with the client_id only, with no client secret,");
        });
    }

    @Test
    void clientAuthenticationEvidenceAttachesTheAcceptedRefreshWhoseTokenWorksWhenTheFirstOneIsUnusable() {
        server.acceptsMissingSecret = true;
        server.acceptsWrongSecret = true;
        server.mcpEndpointRefusesTokensIssuedWithoutSecret = true;

        List<AuditIssue> issues = audit(strategy(CLIENT_SECRET, ClientType.CONFIDENTIAL_REGISTERED));

        assertThat(issues).singleElement().satisfies(issue -> {
            assertThat(issue.requestResponses()).extracting(this::label)
                    .containsExactly("wrong-secret-refresh", "tools/list", "unissued-refresh");
            assertThat(issue.requestResponses().get(1).response().statusCode()).isEqualTo((short) 200);
            assertThat(issue.detail()).contains("Attached: the refresh with the client_id with a wrong client secret, "
                    + "the MCP tools/list request sent with the access token it issued, and the refused refresh "
                    + "with the unissued refresh token.");
        });
    }

    @Test
    void scopeExpansionEvidenceIsTheDeclaringControlRefreshTheExpandingRefreshAndItsToolsList() {
        server.expandsScope = true;
        server.clientSecret = null;

        List<AuditIssue> issues = audit(strategy(null, ClientType.PUBLIC));

        assertThat(issues).singleElement().satisfies(issue -> {
            assertThat(issue.requestResponses()).extracting(this::label)
                    .containsExactly("client-id-only-refresh", "scope-refresh", "tools/list");
            assertThat(issue.detail()).contains("Attached: the plain refresh that declared the original scope, "
                    + "the refresh that requested the extra scope, and the MCP tools/list request sent with the "
                    + "access token it issued.");
        });
    }

    @Test
    void scopeExpansionEvidenceOmitsTheControlRefreshWhenItDidNotDeclareTheOriginalScope() {
        server.expandsScope = true;
        server.declaresScopeOnlyOnProbes = true;
        server.clientSecret = null;

        List<AuditIssue> issues = audit(strategy(null, ClientType.PUBLIC));

        assertThat(issues).singleElement().satisfies(issue -> {
            assertThat(issue.requestResponses()).extracting(this::label)
                    .containsExactly("scope-refresh", "tools/list");
            assertThat(issue.detail()).contains("Attached: the refresh that requested the extra scope, and the MCP "
                    + "tools/list request sent with the access token it issued.");
        });
    }

    private String label(HttpRequestResponse exchange) {
        HttpRequest request = exchange.request();
        if (request.url().startsWith(MCP_URL)) {
            return request.bodyToString().contains("tools/list") ? "tools/list" : "mcp";
        }
        String body = request.bodyToString();
        if (body.contains("mcp-scanner-unissued-")) {
            return "unissued-refresh";
        }
        if (body.contains("scope=")) {
            return "scope-refresh";
        }
        if (!request.hasHeader("Authorization")) {
            return server.clientSecret == null ? "client-id-only-refresh" : "omitted-secret-refresh";
        }
        return BasicCredentials.header(CLIENT_ID, RefreshRequestFactory.WRONG_SECRET)
                .equals(request.headerValue("Authorization")) ? "wrong-secret-refresh" : "registered-refresh";
    }

    @Test
    void reportsTheWrongSecretVariantSeparatelyFromTheOmittedOne() {
        server.acceptsWrongSecret = true;

        List<AuditIssue> issues = audit(strategy(CLIENT_SECRET, ClientType.CONFIDENTIAL_REGISTERED));

        assertThat(issues).singleElement().satisfies(issue -> assertThat(issue.detail())
                .contains("wrong client secret").doesNotContain("no client secret"));
    }

    @Test
    void staysSilentWhenTheServerAuthenticatesTheClientAndRefusesScopeExpansion() {
        assertThat(audit(strategy(CLIENT_SECRET, ClientType.CONFIDENTIAL_REGISTERED))).isEmpty();
    }

    @Test
    void neverSendsUnauthenticatedRefreshesForAPublicClient() {
        server.clientSecret = null;
        server.acceptsMissingSecret = true;

        List<AuditIssue> issues = audit(strategy(null, ClientType.PUBLIC));

        assertThat(issues).isEmpty();
        assertThat(server.tokenAuthorizations).containsOnlyNulls();
        assertThat(server.tokenRequests).noneMatch(form -> "mcp-scanner-wrong-client-secret".equals(form.get("client_secret")));
        assertThat(server.tokenRequests).hasSize(3);
    }

    @Test
    void aConfiguredSecretIsOnlyTentativeWhileTheServerAlsoAdmitsPublicClients() {
        server.acceptsMissingSecret = true;
        server.authMethodsSupported = List.of("none", "client_secret_basic");

        List<AuditIssue> issues = audit(strategy(CLIENT_SECRET, ClientType.CONFIDENTIAL_CONFIGURED));

        assertThat(issues).singleElement().satisfies(issue -> {
            assertThat(issue.confidence()).isEqualTo(AuditIssueConfidence.TENTATIVE);
            assertThat(issue.detail()).contains("could not confirm");
        });
    }

    @Test
    void aConfiguredSecretIsFirmWhenTheServerAdmitsOnlyConfidentialClients() {
        server.acceptsMissingSecret = true;

        List<AuditIssue> issues = audit(strategy(CLIENT_SECRET, ClientType.CONFIDENTIAL_CONFIGURED));

        assertThat(issues).singleElement().extracting(AuditIssue::confidence).isEqualTo(AuditIssueConfidence.FIRM);
    }

    @Test
    void reportsScopeExpansionAndNarrowsTheLiveSessionBack() {
        server.expandsScope = true;
        OAuthAuthCodeStrategy strategy = strategy(null, ClientType.PUBLIC);
        server.clientSecret = null;

        List<AuditIssue> issues = audit(strategy);

        assertThat(issues).singleElement().satisfies(issue -> {
            assertThat(issue.name()).isEqualTo(OAuthRefreshGrantIssues.SCOPE_EXPANSION_ISSUE);
            assertThat(issue.confidence()).isEqualTo(AuditIssueConfidence.FIRM);
            assertThat(issue.detail()).contains("mcp:admin");
        });
        assertThat(server.scopeOfAccessToken(liveAccessToken(strategy))).contains("mcp:tools");
    }

    @Test
    void doesNotClaimTheOriginalGrantLackedTheScopeWhenTheServerNeverDeclaredTheOriginalScope() {
        server.expandsScope = true;
        server.declaresScopeOnlyOnProbes = true;
        OAuthAuthCodeStrategy strategy = strategy(null, ClientType.PUBLIC);
        server.clientSecret = null;

        List<AuditIssue> issues = audit(strategy);

        assertThat(issues).singleElement().satisfies(issue -> {
            assertThat(issue.name()).isEqualTo(OAuthRefreshGrantIssues.SCOPE_EXPANSION_ISSUE);
            assertThat(issue.confidence()).isEqualTo(AuditIssueConfidence.TENTATIVE);
            assertThat(issue.detail()).doesNotContain("the original grant did not include")
                    .contains("the extension did not request");
        });
    }

    @Test
    void statesTheOriginalGrantLackedTheScopeWhenTheServerDeclaredIt() {
        server.expandsScope = true;
        OAuthAuthCodeStrategy strategy = strategy(null, ClientType.PUBLIC);
        server.clientSecret = null;

        assertThat(audit(strategy)).singleElement().extracting(AuditIssue::detail).asString()
                .contains("the original grant did not include");
    }

    @Test
    void cannotProveScopeExpansionWhenTheServerNeverDeclaresTheGrantedScope() {
        server.expandsScope = true;
        server.declaresScope = false;

        List<AuditIssue> issues = audit(strategy(CLIENT_SECRET, ClientType.CONFIDENTIAL_REGISTERED));

        assertThat(issues).isEmpty();
    }

    @Test
    void doesNotProbeScopeWhenNoUngrantedPrivilegeScopeIsAdvertised() {
        server.expandsScope = true;
        server.scopesSupported = List.of("mcp:tools", "openid", "offline_access");

        assertThat(audit(strategy(CLIENT_SECRET, ClientType.CONFIDENTIAL_REGISTERED))).isEmpty();
        assertThat(server.tokenRequests).noneMatch(form -> form.containsKey("scope"));
    }

    @Test
    void keepsTheLiveSessionUsableWhenTheServerRotatesRefreshTokens() {
        server.rotatesRefreshTokens = true;
        server.acceptsMissingSecret = true;
        server.acceptsWrongSecret = true;
        server.expandsScope = true;
        OAuthAuthCodeStrategy strategy = strategy(CLIENT_SECRET, ClientType.CONFIDENTIAL_REGISTERED);

        List<AuditIssue> issues = audit(strategy);

        assertThat(issues).hasSize(2);
        assertThat(server.refreshTokenIsLive(LIVE_REFRESH_TOKEN)).isFalse();
        assertThat(server.refreshTokenIsLive(strategy.refreshToken().getValue())).isTrue();
        assertThat(server.scopeOfAccessToken(liveAccessToken(strategy))).contains("mcp:tools");
    }

    @Test
    void neverPresentsARefreshTokenThatWasRotatedAway() {
        server.rotatesRefreshTokens = true;
        server.acceptsMissingSecret = true;
        server.acceptsWrongSecret = true;
        server.expandsScope = true;

        audit(strategy(CLIENT_SECRET, ClientType.CONFIDENTIAL_REGISTERED));

        assertThat(server.tokenRequests).hasSizeGreaterThan(6);
        assertThat(server.staleRefreshTokenPresentations).isZero();
    }

    @Test
    void staysSilentAndStopsWhenEvenTheAuthenticatedRefreshIsRefused() {
        server.refusesEveryRefresh = true;
        server.acceptsMissingSecret = true;

        assertThat(audit(strategy(CLIENT_SECRET, ClientType.CONFIDENTIAL_REGISTERED))).isEmpty();
        assertThat(server.tokenRequests).hasSize(1);
    }

    @Test
    void staysSilentWhenTheServerAcceptsUnissuedRefreshTokens() {
        server.acceptsUnissuedRefreshTokens = true;
        server.acceptsMissingSecret = true;

        assertThat(audit(strategy(CLIENT_SECRET, ClientType.CONFIDENTIAL_REGISTERED))).isEmpty();
    }

    @Test
    void isTentativeWhenTheMcpEndpointCannotProveTheTokenWorks() {
        server.acceptsMissingSecret = true;
        server.mcpEndpointOpenToAnonymous = true;

        List<AuditIssue> issues = audit(strategy(CLIENT_SECRET, ClientType.CONFIDENTIAL_REGISTERED));

        assertThat(issues).singleElement().satisfies(issue -> {
            assertThat(issue.confidence()).isEqualTo(AuditIssueConfidence.TENTATIVE);
            assertThat(issue.detail()).contains("could not be verified");
        });
    }

    @Test
    void reportsAnUnauthenticatedRefreshTentativelyWhenTheMcpEndpointRefusesItsTokenButNeverTheScope() {
        server.acceptsMissingSecret = true;
        server.expandsScope = true;
        server.mcpEndpointRefusesProbeTokens = true;

        List<AuditIssue> issues = audit(strategy(CLIENT_SECRET, ClientType.CONFIDENTIAL_REGISTERED));

        assertThat(issues).singleElement().satisfies(issue -> {
            assertThat(issue.name()).isEqualTo(OAuthRefreshGrantIssues.CLIENT_AUTHENTICATION_ISSUE);
            assertThat(issue.confidence()).isEqualTo(AuditIssueConfidence.TENTATIVE);
            assertThat(issue.detail()).contains("was refused by the MCP endpoint");
        });
    }

    @Test
    void judgesEachProbeTokenBeforeTheSessionReplacesIt() {
        server.acceptsMissingSecret = true;
        server.expandsScope = true;
        server.revokesPreviousAccessTokens = true;

        List<AuditIssue> issues = audit(strategy(CLIENT_SECRET, ClientType.CONFIDENTIAL_REGISTERED));

        assertThat(issues).hasSize(2).allSatisfy(issue ->
                assertThat(issue.confidence()).isEqualTo(AuditIssueConfidence.FIRM));
    }

    @Test
    void narrowsTheLiveSessionBackEvenWhenTheServerNeverDeclaresTheGrantedScope() {
        server.expandsScope = true;
        server.declaresScope = false;
        OAuthAuthCodeStrategy strategy = strategy(CLIENT_SECRET, ClientType.CONFIDENTIAL_REGISTERED);

        audit(strategy);

        assertThat(server.scopeOfAccessToken(liveAccessToken(strategy))).contains("mcp:tools");
    }

    @Test
    void staysSilentWhenTheMetadataDeclaresAnotherIssuer() {
        server.acceptsMissingSecret = true;
        server.metadataIssuer = "https://evil.example";

        assertThat(audit(strategy(CLIENT_SECRET, ClientType.CONFIDENTIAL_REGISTERED))).isEmpty();
        assertThat(server.tokenRequests).isEmpty();
    }

    @Test
    void reauthenticatesTheLiveSessionAfterAnUnauthenticatedRefreshIsAccepted() {
        server.acceptsMissingSecret = true;
        server.mcpEndpointRefusesProbeTokens = true;
        OAuthAuthCodeStrategy strategy = strategy(CLIENT_SECRET, ClientType.CONFIDENTIAL_REGISTERED);

        audit(strategy);

        String liveAuthorization = server.tokenAuthorizations.get(server.tokenAuthorizations.size() - 1);
        assertThat(liveAuthorization).startsWith("Basic ");
        assertThat(server.scopeOfAccessToken(liveAccessToken(strategy))).contains("mcp:tools");
        assertThat(liveAccessToken(strategy)).isNotEqualTo("live-access-token-0");
    }

    @Test
    void staysSilentWithoutAuthorizationServerMetadata() {
        server.servesMetadata = false;
        server.acceptsMissingSecret = true;

        assertThat(audit(strategy(CLIENT_SECRET, ClientType.CONFIDENTIAL_REGISTERED))).isEmpty();
        assertThat(server.tokenRequests).isEmpty();
    }

    @Test
    void evidenceCarriesTheRawTokensExchanged() {
        server.acceptsMissingSecret = true;
        server.acceptsWrongSecret = true;
        server.expandsScope = true;
        server.rotatesRefreshTokens = true;

        List<AuditIssue> issues = audit(strategy(CLIENT_SECRET, ClientType.CONFIDENTIAL_REGISTERED));

        assertThat(issues).hasSize(2).allSatisfy(issue -> assertThat(rawText(issue))
                .contains("issued-access-token")
                .containsAnyOf(LIVE_REFRESH_TOKEN, "rotated-refresh-token")
                .doesNotContainIgnoringCase("redacted"));
        assertThat(issues.stream().map(OAuthRefreshGrantCheckTest::rawText).reduce("", String::concat))
                .contains(java.util.Base64.getEncoder().encodeToString(
                        (CLIENT_ID + ":" + CLIENT_SECRET).getBytes()));
    }

    @Test
    void evidenceKeepsTokensWithUrlSignificantCharactersUnchanged() {
        server.acceptsMissingSecret = true;
        server.expandsScope = true;
        server.rotatesRefreshTokens = true;
        server.tokenSuffix = "+a/b==";

        List<AuditIssue> issues = audit(strategy(CLIENT_SECRET, ClientType.CONFIDENTIAL_REGISTERED));

        assertThat(issues).hasSize(2).allSatisfy(issue -> assertThat(rawText(issue))
                .containsPattern("issued-access-token-\\d+\\+a\\\\?/b=="));
    }

    private static String rawText(AuditIssue issue) {
        return issue.requestResponses().stream()
                .map(exchange -> exchange.request().bodyToString() + " " + exchange.request().headerValue("Authorization")
                        + " " + (exchange.response() == null ? "" : exchange.response().bodyToString()))
                .reduce("", String::concat);
    }

    private List<AuditIssue> audit(AuthStrategy strategy) {
        return check(strategy).audit(mcpBase(), server.http());
    }

    private static OAuthRefreshGrantCheck check(AuthStrategy strategy) {
        return new OAuthRefreshGrantCheck(() -> strategy, McpEventLog.noop());
    }

    private List<AuditIssue> auditLogging(AuthStrategy strategy) {
        return new OAuthRefreshGrantCheck(() -> strategy, eventLog).audit(mcpBase(), server.http());
    }

    @Test
    void aSessionWithoutARefreshTokenIsSkippedForAMissingPrerequisite() {
        auditLogging(new BearerTokenAuthStrategy("static"));

        verify(eventLog).info(PREFIX + "skipped " + MCP_URL
                + " (prerequisite missing: the OAuth session holds no refresh token)");
    }

    @Test
    void missingAuthorizationServerMetadataIsSkippedForAMissingPrerequisite() {
        server.servesMetadata = false;

        auditLogging(strategy(CLIENT_SECRET, ClientType.CONFIDENTIAL_REGISTERED));

        verify(eventLog).info(PREFIX + "skipped " + MCP_URL + " (prerequisite missing: no authorization server "
                + "metadata with a token endpoint for " + ORIGIN + ")");
    }

    @Test
    void metadataCutShortByHttp429IsLoggedAsRateLimited() {
        server.throttlesMetadata = true;

        auditLogging(strategy(CLIENT_SECRET, ClientType.CONFIDENTIAL_REGISTERED));

        verify(eventLog).info(PREFIX + "stopped " + MCP_URL + " (rate limited: the server answered HTTP 429)");
    }

    @Test
    void aRefusedControlRefreshStopsTheProbe() {
        server.refusesEveryRefresh = true;

        auditLogging(strategy(CLIENT_SECRET, ClientType.CONFIDENTIAL_REGISTERED));

        verify(eventLog).info(PREFIX + "skipped " + MCP_URL
                + " (prerequisite missing: the control refresh of the live grant was refused with HTTP 400)");
    }

    @Test
    void aControlRefreshAnsweredWithHttp429IsLoggedAsRateLimited() {
        server.throttlesTokens = true;

        auditLogging(strategy(CLIENT_SECRET, ClientType.CONFIDENTIAL_REGISTERED));

        verify(eventLog).info(PREFIX + "stopped " + MCP_URL + " (rate limited: the server answered HTTP 429)");
    }

    @Test
    void aCompleteProbeLogsNoSkip() {
        auditLogging(strategy(CLIENT_SECRET, ClientType.CONFIDENTIAL_REGISTERED));

        verify(eventLog, never()).info(contains("skipped"));
        verify(eventLog, never()).info(contains("stopped"));
    }

    private static String liveAccessToken(OAuthAuthCodeStrategy strategy) {
        return strategy.headers().get("Authorization").substring("Bearer ".length());
    }

    private static OAuthAuthCodeStrategy strategy(String secret, ClientType type) {
        TestOAuthStrategies.Client client = switch (type) {
            case PUBLIC -> new TestOAuthStrategies.Client(CLIENT_ID, secret, "none", RegistrationMode.DCR);
            case CONFIDENTIAL_REGISTERED ->
                    new TestOAuthStrategies.Client(CLIENT_ID, secret, "client_secret_basic", RegistrationMode.DCR);
            case CONFIDENTIAL_CONFIGURED ->
                    new TestOAuthStrategies.Client(CLIENT_ID, secret, "client_secret_basic", RegistrationMode.PRE_REGISTERED);
        };
        return TestOAuthStrategies.authenticated(new TestOAuthStrategies.Login(URI.create(ORIGIN), URI.create(MCP_URL),
                List.of("mcp:tools"), client, "live-access-token-0", LIVE_REFRESH_TOKEN, Instant.now().plusSeconds(3600),
                Clock.systemUTC()), TestOAuthStrategies.refusingRefresh());
    }

    static HttpRequestResponse mcpBase() {
        HttpRequest request = HttpRequest.httpRequestFromUrl(MCP_URL).withMethod("POST")
                .withHeader("Content-Type", "application/json")
                .withHeader("Authorization", "Bearer live-access-token-0")
                .withBody("{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/call\",\"params\":{\"name\":\"read_note\"}}");
        HttpResponse response = HttpResponse.httpResponse("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n"
                + "{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{\"content\":[]}}");
        return HttpRequestResponse.httpRequestResponse(request, response);
    }

    private static HttpRequestResponse nonMcpBase() {
        HttpRequest request = HttpRequest.httpRequestFromUrl("https://mcp.example/index.html");
        return HttpRequestResponse.httpRequestResponse(request,
                HttpResponse.httpResponse("HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n<html></html>"));
    }
}
