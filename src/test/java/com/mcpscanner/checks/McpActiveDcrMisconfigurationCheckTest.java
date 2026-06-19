package com.mcpscanner.checks;

import burp.api.montoya.http.Http;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.api.montoya.scanner.audit.issues.AuditIssue;
import burp.api.montoya.scanner.audit.issues.AuditIssueConfidence;
import burp.api.montoya.scanner.audit.issues.AuditIssueSeverity;
import burp.api.montoya.scanner.scancheck.ActiveScanCheck;
import com.mcpscanner.checks.registry.ScanCheckSettings;
import com.mcpscanner.logging.McpEventLog;
import com.mcpscanner.scan.ScanStartContext;
import com.mcpscanner.testutil.MontoyaTestFactory;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyBoolean;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.contains;
import static org.mockito.Mockito.atLeastOnce;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class McpActiveDcrMisconfigurationCheckTest {

    private static final String ISSUE_NAME = "MCP OAuth DCR Misconfiguration";
    private static final String ENDPOINT = "https://mcp.example.com/mcp";

    private static final String AS_BODY_HTTPS_ISSUER = "{\n"
            + "  \"issuer\": \"https://auth.example.com\",\n"
            + "  \"authorization_endpoint\": \"https://auth.example.com/authorize\",\n"
            + "  \"token_endpoint\": \"https://auth.example.com/token\",\n"
            + "  \"registration_endpoint\": \"https://auth.example.com/register\"\n"
            + "}";

    private static final String AS_BODY_NO_REGISTRATION = "{\n"
            + "  \"issuer\": \"https://auth.example.com\",\n"
            + "  \"authorization_endpoint\": \"https://auth.example.com/authorize\",\n"
            + "  \"token_endpoint\": \"https://auth.example.com/token\"\n"
            + "}";

    private static final String AS_BODY_NO_AUTHORIZE = "{\n"
            + "  \"issuer\": \"https://auth.example.com\",\n"
            + "  \"token_endpoint\": \"https://auth.example.com/token\",\n"
            + "  \"registration_endpoint\": \"https://auth.example.com/register\"\n"
            + "}";

    private static final String AS_BODY_HTTP_ISSUER = "{\n"
            + "  \"issuer\": \"http://auth.example.com\",\n"
            + "  \"authorization_endpoint\": \"http://auth.example.com/authorize\",\n"
            + "  \"token_endpoint\": \"http://auth.example.com/token\",\n"
            + "  \"registration_endpoint\": \"http://auth.example.com/register\"\n"
            + "}";

    private static final String PRM_BODY_POINTING_AT_AS = "{\n"
            + "  \"resource\": \"https://mcp.example.com/\",\n"
            + "  \"authorization_servers\": [\"https://auth.example.com\"]\n"
            + "}";

    private static final String CLIENT_REGISTRATION_OK_BODY = "{\n"
            + "  \"client_id\": \"abc123\",\n"
            + "  \"client_name\": \"scanner-probe\"\n"
            + "}";

    private static String registrationEchoingRedirect(String redirectUri) {
        return "{\n"
                + "  \"client_id\": \"abc123\",\n"
                + "  \"client_name\": \"scanner-probe\",\n"
                + "  \"redirect_uris\": [\"" + redirectUri.replace("\"", "\\\"") + "\"]\n"
                + "}";
    }

    private static final String JAVASCRIPT_REDIRECT = "javascript:alert(1)";
    private static final String DATA_REDIRECT = "data:text/html,<script>1</script>";
    private static final String WILDCARD_REDIRECT = "https://*.attacker.example/cb";
    private static final String PATH_TRAVERSAL_REDIRECT = "https://server.example/cb/../bypass";
    private static final String HTTP_DOWNGRADE_REDIRECT = "http://attacker.example/cb";

    @BeforeAll
    static void installFactory() {
        MontoyaTestFactory.install();
    }

    @Mock private Http http;
    @Mock private ScanCheckSettings settings;

    private McpActiveDcrMisconfigurationCheck check;
    private final ScanStartContext context = new ScanStartContext(ENDPOINT, Map.of());

    @BeforeEach
    void setUp() {
        lenient().when(settings.isEnabled(anyString(), anyBoolean())).thenReturn(true);
        check = dcrCheck(settings, null);
    }

    @Test
    void noRegistrationEndpointAdvertised_returnsEmpty() {
        HttpRequestResponse unauthChallenge = httpRequestResponse(401, "");
        HttpRequestResponse asWithoutRegistration = httpRequestResponse(200, AS_BODY_NO_REGISTRATION);
        when(http.sendRequest(any(HttpRequest.class))).thenReturn(unauthChallenge, asWithoutRegistration);

        List<AuditIssue> issues = check.runOnceForSession(context, http);

        assertThat(issues).isEmpty();
    }

    @Test
    void gatedRegistrationReturns401_returnsEmpty() {
        HttpRequestResponse unauthChallenge = httpRequestResponse(401, "");
        HttpRequestResponse asMetadata = httpRequestResponse(200, AS_BODY_HTTPS_ISSUER);
        HttpRequestResponse gatedRegistration = httpRequestResponse(401, "");
        when(http.sendRequest(any(HttpRequest.class)))
                .thenReturn(unauthChallenge, asMetadata, gatedRegistration);

        List<AuditIssue> issues = check.runOnceForSession(context, http);

        assertThat(issues).isEmpty();
    }

    @Test
    void openRegistrationWithNoHostileRedirectEchoed_raisesNoIssueButLogsInformationalLine() {
        McpEventLog eventLog = mock(McpEventLog.class);
        check = dcrCheck(settings, eventLog);
        HttpRequestResponse unauthChallenge = httpRequestResponse(401, "");
        HttpRequestResponse asMetadata = httpRequestResponse(200, AS_BODY_HTTPS_ISSUER);
        HttpRequestResponse openRegistration = httpRequestResponse(201, CLIENT_REGISTRATION_OK_BODY);
        HttpRequestResponse phaseBRejected = httpRequestResponse(400, "{\"error\":\"invalid_redirect_uri\"}");
        when(http.sendRequest(any(HttpRequest.class)))
                .thenReturn(unauthChallenge, asMetadata, openRegistration,
                        phaseBRejected, phaseBRejected, phaseBRejected, phaseBRejected, phaseBRejected);

        List<AuditIssue> issues = check.runOnceForSession(context, http);

        assertThat(issues).isEmpty();
        verify(eventLog, atLeastOnce()).info(contains("open registration"));
    }

    @Test
    void openRegistrationPlusUnsafeRedirectUri_listsBothSignalsInDetail() {
        HttpRequestResponse unauthChallenge = httpRequestResponse(401, "");
        HttpRequestResponse asMetadata = httpRequestResponse(200, AS_BODY_HTTPS_ISSUER);
        HttpRequestResponse openRegistration = httpRequestResponse(201, CLIENT_REGISTRATION_OK_BODY);
        HttpRequestResponse rejected = httpRequestResponse(400, "{\"error\":\"invalid_redirect_uri\"}");
        HttpRequestResponse pathTraversalAccepted = httpRequestResponse(201,
                registrationEchoingRedirect(PATH_TRAVERSAL_REDIRECT));
        HttpRequestResponse honored = redirectTo(PATH_TRAVERSAL_REDIRECT + "?code=abc");
        when(http.sendRequest(any(HttpRequest.class)))
                .thenReturn(unauthChallenge, asMetadata, openRegistration,
                        rejected, rejected, rejected, pathTraversalAccepted, rejected, honored);

        List<AuditIssue> issues = check.runOnceForSession(context, http);

        assertThat(issues).hasSize(1);
        AuditIssue issue = issues.get(0);
        assertThat(issue.severity()).isEqualTo(AuditIssueSeverity.MEDIUM);
        assertThat(issue.detail()).contains("unauthenticated client registration");
        assertThat(issue.detail()).contains("hostile redirect");
        assertThat(issue.detail()).contains("authorization endpoint");
        assertThat(issue.detail()).contains("path-traversal in path");
    }

    @Test
    void javascriptSchemeHonoredAtAuthorizeRaisesIssueToHigh() {
        HttpRequestResponse unauthChallenge = httpRequestResponse(401, "");
        HttpRequestResponse asMetadata = httpRequestResponse(200, AS_BODY_HTTPS_ISSUER);
        HttpRequestResponse openRegistration = httpRequestResponse(201, CLIENT_REGISTRATION_OK_BODY);
        HttpRequestResponse jsAccepted = httpRequestResponse(201,
                registrationEchoingRedirect(JAVASCRIPT_REDIRECT));
        HttpRequestResponse rejected = httpRequestResponse(400, "{\"error\":\"invalid_redirect_uri\"}");
        HttpRequestResponse jsHonored = redirectTo(JAVASCRIPT_REDIRECT);
        when(http.sendRequest(any(HttpRequest.class)))
                .thenReturn(unauthChallenge, asMetadata, openRegistration,
                        jsAccepted, rejected, rejected, rejected, rejected, jsHonored);

        List<AuditIssue> issues = check.runOnceForSession(context, http);

        assertThat(issues).hasSize(1);
        AuditIssue issue = issues.get(0);
        assertThat(issue.severity()).isEqualTo(AuditIssueSeverity.HIGH);
        assertThat(issue.detail()).contains("javascript: scheme");
    }

    @Test
    void javascriptSchemeEchoedButRejectedAtAuthorize_raisesNoIssue() {
        // The register-echo-vs-authorize-enforcement FP-suppression keystone: /register echoes javascript:, but
        // GET /authorize with it returns HTTP 400 — enforcement happens at /authorize.
        HttpRequestResponse unauthChallenge = httpRequestResponse(401, "");
        HttpRequestResponse asMetadata = httpRequestResponse(200, AS_BODY_HTTPS_ISSUER);
        HttpRequestResponse openRegistration = httpRequestResponse(201, CLIENT_REGISTRATION_OK_BODY);
        HttpRequestResponse jsEchoed = httpRequestResponse(201,
                registrationEchoingRedirect(JAVASCRIPT_REDIRECT));
        HttpRequestResponse rejected = httpRequestResponse(400, "{\"error\":\"invalid_redirect_uri\"}");
        HttpRequestResponse authorizeRejected = httpRequestResponse(400, "{\"error\":\"invalid_request\"}");
        when(http.sendRequest(any(HttpRequest.class)))
                .thenReturn(unauthChallenge, asMetadata, openRegistration,
                        jsEchoed, rejected, rejected, rejected, rejected, authorizeRejected);

        List<AuditIssue> issues = check.runOnceForSession(context, http);

        assertThat(issues).isEmpty();
    }

    @Test
    void dataSchemeHonoredAtAuthorizeRaisesIssueToHigh() {
        HttpRequestResponse unauthChallenge = httpRequestResponse(401, "");
        HttpRequestResponse asMetadata = httpRequestResponse(200, AS_BODY_HTTPS_ISSUER);
        HttpRequestResponse openRegistration = httpRequestResponse(201, CLIENT_REGISTRATION_OK_BODY);
        HttpRequestResponse rejected = httpRequestResponse(400, "{\"error\":\"invalid_redirect_uri\"}");
        HttpRequestResponse dataAccepted = httpRequestResponse(201,
                registrationEchoingRedirect(DATA_REDIRECT));
        HttpRequestResponse dataHonored = redirectTo(DATA_REDIRECT);
        when(http.sendRequest(any(HttpRequest.class)))
                .thenReturn(unauthChallenge, asMetadata, openRegistration,
                        rejected, dataAccepted, rejected, rejected, rejected, dataHonored);

        List<AuditIssue> issues = check.runOnceForSession(context, http);

        assertThat(issues).hasSize(1);
        AuditIssue issue = issues.get(0);
        assertThat(issue.severity()).isEqualTo(AuditIssueSeverity.HIGH);
        assertThat(issue.detail()).contains("data: scheme");
    }

    @Test
    void wildcardSubdomainHonoredAtAuthorizeRaisesIssueToHigh() {
        // Wildcard echoed at /register, then a DIFFERENT concrete subdomain is honored at
        // /authorize (real pattern-expansion). Production mints a runtime-random concrete
        // subdomain, so we capture the redirect_uri actually sent to /authorize and stub the
        // Location to START WITH it (proving the honored-wildcard path, not a hardcoded match).
        HttpRequestResponse unauthChallenge = httpRequestResponse(401, "");
        HttpRequestResponse asMetadata = httpRequestResponse(200, AS_BODY_HTTPS_ISSUER);
        HttpRequestResponse openRegistration = httpRequestResponse(201, CLIENT_REGISTRATION_OK_BODY);
        HttpRequestResponse rejected = httpRequestResponse(400, "{\"error\":\"invalid_redirect_uri\"}");
        HttpRequestResponse wildcardAccepted = httpRequestResponse(201,
                registrationEchoingRedirect(WILDCARD_REDIRECT));
        HttpRequestResponse authorizeHonored = redirectTo("PLACEHOLDER");
        ArgumentCaptor<HttpRequest> captor = ArgumentCaptor.forClass(HttpRequest.class);
        when(http.sendRequest(captor.capture()))
                .thenReturn(unauthChallenge, asMetadata, openRegistration,
                        rejected, rejected, wildcardAccepted, rejected, rejected, authorizeHonored);

        // The last request is the Phase C GET /authorize for the wildcard probe. Mirror its
        // redirect_uri into the honored Location so startsWith matches the runtime-random target.
        lenient().when(authorizeHonored.response().headerValue("Location"))
                .thenAnswer(invocation -> capturedAuthorizeRedirectUri(captor) + "?code=abc");

        List<AuditIssue> issues = check.runOnceForSession(context, http);

        assertThat(issues).hasSize(1);
        AuditIssue issue = issues.get(0);
        assertThat(issue.severity()).isEqualTo(AuditIssueSeverity.HIGH);
        assertThat(issue.detail()).contains("wildcard host");
    }

    @Test
    void pathTraversalLoginBounceAtAuthorize_isInconclusive_raisesNoIssue() {
        // Regression: PATH_TRAVERSAL is an https probe. A normal login-bounce 302 to an
        // unrelated https URL must NOT be treated as honoring the hostile redirect.
        HttpRequestResponse unauthChallenge = httpRequestResponse(401, "");
        HttpRequestResponse asMetadata = httpRequestResponse(200, AS_BODY_HTTPS_ISSUER);
        HttpRequestResponse openRegistration = httpRequestResponse(201, CLIENT_REGISTRATION_OK_BODY);
        HttpRequestResponse rejected = httpRequestResponse(400, "{\"error\":\"invalid_redirect_uri\"}");
        HttpRequestResponse pathTraversalAccepted = httpRequestResponse(201,
                registrationEchoingRedirect(PATH_TRAVERSAL_REDIRECT));
        HttpRequestResponse loginBounce = redirectTo("https://login.example/login?return_to=%2Fauthorize");
        when(http.sendRequest(any(HttpRequest.class)))
                .thenReturn(unauthChallenge, asMetadata, openRegistration,
                        rejected, rejected, rejected, pathTraversalAccepted, rejected, loginBounce);

        List<AuditIssue> issues = check.runOnceForSession(context, http);

        assertThat(issues).isEmpty();
    }

    @Test
    void wildcardLoginBounceAtAuthorize_isInconclusive_raisesNoIssue() {
        // Regression: WILDCARD_HOST is an https probe. A normal login-bounce 302 to an
        // unrelated https URL must NOT be treated as honoring the hostile redirect.
        HttpRequestResponse unauthChallenge = httpRequestResponse(401, "");
        HttpRequestResponse asMetadata = httpRequestResponse(200, AS_BODY_HTTPS_ISSUER);
        HttpRequestResponse openRegistration = httpRequestResponse(201, CLIENT_REGISTRATION_OK_BODY);
        HttpRequestResponse rejected = httpRequestResponse(400, "{\"error\":\"invalid_redirect_uri\"}");
        HttpRequestResponse wildcardAccepted = httpRequestResponse(201,
                registrationEchoingRedirect(WILDCARD_REDIRECT));
        HttpRequestResponse loginBounce = redirectTo("https://login.example/login?return_to=%2Fauthorize");
        when(http.sendRequest(any(HttpRequest.class)))
                .thenReturn(unauthChallenge, asMetadata, openRegistration,
                        rejected, rejected, wildcardAccepted, rejected, rejected, loginBounce);

        List<AuditIssue> issues = check.runOnceForSession(context, http);

        assertThat(issues).isEmpty();
    }

    private static String capturedAuthorizeRedirectUri(ArgumentCaptor<HttpRequest> captor) {
        String url = captor.getAllValues().get(captor.getAllValues().size() - 1).url();
        for (String pair : url.substring(url.indexOf('?') + 1).split("&")) {
            if (pair.startsWith("redirect_uri=")) {
                return java.net.URLDecoder.decode(
                        pair.substring("redirect_uri=".length()), java.nio.charset.StandardCharsets.UTF_8);
            }
        }
        throw new IllegalStateException("no redirect_uri in captured authorize URL: " + url);
    }

    @Test
    void wildcardExactMatchOnlyAtAuthorize_raisesNoIssue() {
        // Wildcard echoed at /register, but a DIFFERENT concrete subdomain is REJECTED at
        // /authorize (exact-match storage only, not pattern expansion) — suppress.
        HttpRequestResponse unauthChallenge = httpRequestResponse(401, "");
        HttpRequestResponse asMetadata = httpRequestResponse(200, AS_BODY_HTTPS_ISSUER);
        HttpRequestResponse openRegistration = httpRequestResponse(201, CLIENT_REGISTRATION_OK_BODY);
        HttpRequestResponse rejected = httpRequestResponse(400, "{\"error\":\"invalid_redirect_uri\"}");
        HttpRequestResponse wildcardAccepted = httpRequestResponse(201,
                registrationEchoingRedirect(WILDCARD_REDIRECT));
        HttpRequestResponse subdomainRejected = httpRequestResponse(400, "{\"error\":\"invalid_redirect_uri\"}");
        when(http.sendRequest(any(HttpRequest.class)))
                .thenReturn(unauthChallenge, asMetadata, openRegistration,
                        rejected, rejected, wildcardAccepted, rejected, rejected, subdomainRejected);

        List<AuditIssue> issues = check.runOnceForSession(context, http);

        assertThat(issues).isEmpty();
    }

    @Test
    void pathTraversalHonoredAtAuthorizeStaysMedium() {
        HttpRequestResponse unauthChallenge = httpRequestResponse(401, "");
        HttpRequestResponse asMetadata = httpRequestResponse(200, AS_BODY_HTTPS_ISSUER);
        HttpRequestResponse openRegistration = httpRequestResponse(201, CLIENT_REGISTRATION_OK_BODY);
        HttpRequestResponse rejected = httpRequestResponse(400, "{\"error\":\"invalid_redirect_uri\"}");
        HttpRequestResponse pathTraversalAccepted = httpRequestResponse(201,
                registrationEchoingRedirect(PATH_TRAVERSAL_REDIRECT));
        HttpRequestResponse honored = redirectTo(PATH_TRAVERSAL_REDIRECT + "?code=abc");
        when(http.sendRequest(any(HttpRequest.class)))
                .thenReturn(unauthChallenge, asMetadata, openRegistration,
                        rejected, rejected, rejected, pathTraversalAccepted, rejected, honored);

        List<AuditIssue> issues = check.runOnceForSession(context, http);

        assertThat(issues).hasSize(1);
        AuditIssue issue = issues.get(0);
        assertThat(issue.severity()).isEqualTo(AuditIssueSeverity.MEDIUM);
        assertThat(issue.detail()).contains("path-traversal in path");
    }

    @Test
    void loginBounceAtAuthorize_isInconclusive_raisesNoIssue() {
        // /register echoes javascript:, but /authorize 302-bounces to a login page that
        // merely preserves the authorize URL — it does NOT commit to the hostile redirect.
        // Pre-login bouncing is not proof of honoring — suppress.
        HttpRequestResponse unauthChallenge = httpRequestResponse(401, "");
        HttpRequestResponse asMetadata = httpRequestResponse(200, AS_BODY_HTTPS_ISSUER);
        HttpRequestResponse openRegistration = httpRequestResponse(201, CLIENT_REGISTRATION_OK_BODY);
        HttpRequestResponse jsEchoed = httpRequestResponse(201,
                registrationEchoingRedirect(JAVASCRIPT_REDIRECT));
        HttpRequestResponse rejected = httpRequestResponse(400, "{\"error\":\"invalid_redirect_uri\"}");
        HttpRequestResponse loginBounce = redirectTo("https://auth.example.com/login?return_to=%2Fauthorize");
        when(http.sendRequest(any(HttpRequest.class)))
                .thenReturn(unauthChallenge, asMetadata, openRegistration,
                        jsEchoed, rejected, rejected, rejected, rejected, loginBounce);

        List<AuditIssue> issues = check.runOnceForSession(context, http);

        assertThat(issues).isEmpty();
    }

    @Test
    void noAuthorizationEndpoint_suppressesPhaseC_raisesNoIssue() {
        McpEventLog eventLog = mock(McpEventLog.class);
        check = dcrCheck(settings, eventLog);
        HttpRequestResponse unauthChallenge = httpRequestResponse(401, "");
        HttpRequestResponse asMetadata = httpRequestResponse(200, AS_BODY_NO_AUTHORIZE);
        HttpRequestResponse openRegistration = httpRequestResponse(201, CLIENT_REGISTRATION_OK_BODY);
        HttpRequestResponse jsEchoed = httpRequestResponse(201,
                registrationEchoingRedirect(JAVASCRIPT_REDIRECT));
        HttpRequestResponse rejected = httpRequestResponse(400, "{\"error\":\"invalid_redirect_uri\"}");
        when(http.sendRequest(any(HttpRequest.class)))
                .thenReturn(unauthChallenge, asMetadata, openRegistration,
                        jsEchoed, rejected, rejected, rejected, rejected);

        List<AuditIssue> issues = check.runOnceForSession(context, http);

        assertThat(issues).isEmpty();
        verify(eventLog, atLeastOnce()).info(contains("authorization_endpoint"));
    }

    @Test
    void highTierProbeDominatesWhenBothHighAndMediumHonored() {
        HttpRequestResponse unauthChallenge = httpRequestResponse(401, "");
        HttpRequestResponse asMetadata = httpRequestResponse(200, AS_BODY_HTTPS_ISSUER);
        HttpRequestResponse openRegistration = httpRequestResponse(201, CLIENT_REGISTRATION_OK_BODY);
        HttpRequestResponse jsAccepted = httpRequestResponse(201,
                registrationEchoingRedirect(JAVASCRIPT_REDIRECT));
        HttpRequestResponse downgradeAccepted = httpRequestResponse(201,
                registrationEchoingRedirect(HTTP_DOWNGRADE_REDIRECT));
        HttpRequestResponse rejected = httpRequestResponse(400, "{\"error\":\"invalid_redirect_uri\"}");
        HttpRequestResponse jsHonored = redirectTo(JAVASCRIPT_REDIRECT);
        HttpRequestResponse downgradeHonored = redirectTo(HTTP_DOWNGRADE_REDIRECT + "?code=abc");
        // JAVASCRIPT_SCHEME (HIGH) is probe index 0, HTTP_DOWNGRADE (MEDIUM) is index 4.
        // Both echoed at /register and honored at /authorize.
        when(http.sendRequest(any(HttpRequest.class)))
                .thenReturn(unauthChallenge, asMetadata, openRegistration,
                        jsAccepted, rejected, rejected, rejected, downgradeAccepted,
                        jsHonored, downgradeHonored);

        List<AuditIssue> issues = check.runOnceForSession(context, http);

        assertThat(issues).hasSize(1);
        assertThat(issues.get(0).severity()).isEqualTo(AuditIssueSeverity.HIGH);
    }

    @Test
    void openRegistrationPlusHttpDowngradeHonored_emitsMediumIssue() {
        HttpRequestResponse unauthChallenge = httpRequestResponse(401, "");
        HttpRequestResponse asMetadata = httpRequestResponse(200, AS_BODY_HTTPS_ISSUER);
        HttpRequestResponse openRegistration = httpRequestResponse(201, CLIENT_REGISTRATION_OK_BODY);
        HttpRequestResponse rejected = httpRequestResponse(400, "{\"error\":\"invalid_redirect_uri\"}");
        HttpRequestResponse downgradeAccepted = httpRequestResponse(201,
                registrationEchoingRedirect(HTTP_DOWNGRADE_REDIRECT));
        HttpRequestResponse downgradeHonored = redirectTo(HTTP_DOWNGRADE_REDIRECT + "?code=abc");
        when(http.sendRequest(any(HttpRequest.class)))
                .thenReturn(unauthChallenge, asMetadata, openRegistration,
                        rejected, rejected, rejected, rejected, downgradeAccepted, downgradeHonored);

        List<AuditIssue> issues = check.runOnceForSession(context, http);

        assertThat(issues).hasSize(1);
        AuditIssue issue = issues.get(0);
        assertThat(issue.severity()).isEqualTo(AuditIssueSeverity.MEDIUM);
        assertThat(issue.detail()).contains("http:// downgrade");
    }

    @Test
    void phaseBClassifiedInconclusive_whenResponseOmitsRegisteredRedirectUris() {
        // Server returned client_id but did NOT echo back the unsafe redirect_uri it was
        // submitted (no redirect_uris field at all). The probe cannot prove the unsafe
        // redirect actually survived registration — Phase B must be inconclusive.
        HttpRequestResponse unauthChallenge = httpRequestResponse(401, "");
        HttpRequestResponse asMetadata = httpRequestResponse(200, AS_BODY_HTTPS_ISSUER);
        HttpRequestResponse openRegistration = httpRequestResponse(201, CLIENT_REGISTRATION_OK_BODY);
        // 200/201 + client_id but no redirect_uris field for every Phase B probe.
        HttpRequestResponse missingRedirectField = httpRequestResponse(201, CLIENT_REGISTRATION_OK_BODY);
        when(http.sendRequest(any(HttpRequest.class)))
                .thenReturn(unauthChallenge, asMetadata, openRegistration,
                        missingRedirectField, missingRedirectField, missingRedirectField,
                        missingRedirectField, missingRedirectField);

        List<AuditIssue> issues = check.runOnceForSession(context, http);

        assertThat(issues).isEmpty();
    }

    @Test
    void phaseBClassifiedInconclusive_whenServerSanitizesUnsafeRedirect() {
        // Server returns 201 + client_id, AND a redirect_uris array — but the array does
        // NOT contain the unsafe URI we submitted (the server sanitized / dropped it).
        // The probe cannot demonstrate vulnerability — Phase B must be inconclusive.
        HttpRequestResponse unauthChallenge = httpRequestResponse(401, "");
        HttpRequestResponse asMetadata = httpRequestResponse(200, AS_BODY_HTTPS_ISSUER);
        HttpRequestResponse openRegistration = httpRequestResponse(201, CLIENT_REGISTRATION_OK_BODY);
        HttpRequestResponse sanitized = httpRequestResponse(201,
                registrationEchoingRedirect("https://safe.example/cb"));
        when(http.sendRequest(any(HttpRequest.class)))
                .thenReturn(unauthChallenge, asMetadata, openRegistration,
                        sanitized, sanitized, sanitized, sanitized, sanitized);

        List<AuditIssue> issues = check.runOnceForSession(context, http);

        assertThat(issues).isEmpty();
    }

    @Test
    void phaseBClassifiedVulnerable_onlyWhenResponseEchoesExactSubmittedRedirect() {
        // Server echoes back the exact submitted unsafe javascript: URI in redirect_uris.
        // This is the only shape that proves the unsafe redirect survived registration.
        HttpRequestResponse unauthChallenge = httpRequestResponse(401, "");
        HttpRequestResponse asMetadata = httpRequestResponse(200, AS_BODY_HTTPS_ISSUER);
        HttpRequestResponse openRegistration = httpRequestResponse(201, CLIENT_REGISTRATION_OK_BODY);
        HttpRequestResponse jsEchoed = httpRequestResponse(201,
                registrationEchoingRedirect(JAVASCRIPT_REDIRECT));
        HttpRequestResponse rejected = httpRequestResponse(400, "{\"error\":\"invalid_redirect_uri\"}");
        HttpRequestResponse jsHonored = redirectTo(JAVASCRIPT_REDIRECT);
        when(http.sendRequest(any(HttpRequest.class)))
                .thenReturn(unauthChallenge, asMetadata, openRegistration,
                        jsEchoed, rejected, rejected, rejected, rejected, jsHonored);

        List<AuditIssue> issues = check.runOnceForSession(context, http);

        assertThat(issues).hasSize(1);
        AuditIssue issue = issues.get(0);
        assertThat(issue.severity()).isEqualTo(AuditIssueSeverity.HIGH);
        assertThat(issue.confidence()).isEqualTo(AuditIssueConfidence.FIRM);
        assertThat(issue.detail()).contains("hostile redirect");
        assertThat(issue.detail()).contains("javascript: scheme");
    }

    @Test
    void httpDowngradeIgnoredWhenIssuerIsHttp() {
        HttpRequestResponse unauthChallenge = httpRequestResponse(401, "");
        HttpRequestResponse asMetadata = httpRequestResponse(200, AS_BODY_HTTP_ISSUER);
        HttpRequestResponse openRegistration = httpRequestResponse(201, CLIENT_REGISTRATION_OK_BODY);
        HttpRequestResponse rejected = httpRequestResponse(400, "{\"error\":\"invalid_redirect_uri\"}");
        when(http.sendRequest(any(HttpRequest.class)))
                .thenReturn(unauthChallenge, asMetadata, openRegistration,
                        rejected, rejected, rejected, rejected);

        List<AuditIssue> issues = check.runOnceForSession(context, http);

        // Phase A open, HTTP_DOWNGRADE skipped (issuer is http), all remaining redirect probes
        // rejected — no hostile redirect echoed, so no issue is raised.
        assertThat(issues).isEmpty();
    }

    @Test
    void wwwAuthenticateDiscoveryPath_used() {
        HttpRequestResponse unauthChallenge = httpRequestResponseWithHeader(401,
                "WWW-Authenticate",
                "Bearer realm=\"mcp\", resource_metadata=\"https://mcp.example.com/.well-known/oauth-protected-resource\"",
                "");
        HttpRequestResponse prmOk = httpRequestResponse(200, PRM_BODY_POINTING_AT_AS);
        HttpRequestResponse asMetadata = httpRequestResponse(200, AS_BODY_HTTPS_ISSUER);
        HttpRequestResponse openRegistration = httpRequestResponse(201, CLIENT_REGISTRATION_OK_BODY);
        HttpRequestResponse jsEchoed = httpRequestResponse(201, registrationEchoingRedirect(JAVASCRIPT_REDIRECT));
        HttpRequestResponse rejected = httpRequestResponse(400, "{\"error\":\"invalid_redirect_uri\"}");
        HttpRequestResponse jsHonored = redirectTo(JAVASCRIPT_REDIRECT);
        when(http.sendRequest(any(HttpRequest.class)))
                .thenReturn(unauthChallenge, prmOk, asMetadata, openRegistration,
                        jsEchoed, rejected, rejected, rejected, rejected, jsHonored);

        List<AuditIssue> issues = check.runOnceForSession(context, http);

        assertThat(issues).hasSize(1);
        assertThat(issues.get(0).detail()).contains("unauthenticated client registration");
    }

    @Test
    void wellKnownFallbackPath_used() {
        HttpRequestResponse unauthChallenge = httpRequestResponse(401, "");
        HttpRequestResponse asMetadata = httpRequestResponse(200, AS_BODY_HTTPS_ISSUER);
        HttpRequestResponse openRegistration = httpRequestResponse(201, CLIENT_REGISTRATION_OK_BODY);
        HttpRequestResponse jsEchoed = httpRequestResponse(201, registrationEchoingRedirect(JAVASCRIPT_REDIRECT));
        HttpRequestResponse rejected = httpRequestResponse(400, "{\"error\":\"invalid_redirect_uri\"}");
        HttpRequestResponse jsHonored = redirectTo(JAVASCRIPT_REDIRECT);
        when(http.sendRequest(any(HttpRequest.class)))
                .thenReturn(unauthChallenge, asMetadata, openRegistration,
                        jsEchoed, rejected, rejected, rejected, rejected, jsHonored);

        List<AuditIssue> issues = check.runOnceForSession(context, http);

        assertThat(issues).hasSize(1);
        assertThat(issues.get(0).detail()).contains("unauthenticated client registration");
    }

    @Test
    void doesNotFireWhenMcpProbeReturnsToolErrorEnvelope() {
        // Confirmation: oracle is /register response shape (201 + client_id).
        // A tool-call probe returning result.isError: true must not trigger this check.
        String toolErrorBody =
                "{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{\"content\":[{\"type\":\"text\",\"text\":\"x\"}],\"isError\":true}}";
        HttpRequestResponse toolError = httpRequestResponse(200, toolErrorBody);
        when(http.sendRequest(any(HttpRequest.class))).thenReturn(toolError);

        List<AuditIssue> issues = check.runOnceForSession(context, http);

        assertThat(issues).isEmpty();
    }

    @Test
    void runsOncePerHost() {
        // A "secure" run that returns no issues still claims the host — successive
        // invocations against the same host MUST short-circuit.
        HttpRequestResponse unauthChallenge = httpRequestResponse(401, "");
        HttpRequestResponse asWithoutRegistration = httpRequestResponse(200, AS_BODY_NO_REGISTRATION);
        when(http.sendRequest(any(HttpRequest.class))).thenReturn(
                unauthChallenge, asWithoutRegistration,
                unauthChallenge, asWithoutRegistration);

        check.runOnceForSession(context, http);
        check.runOnceForSession(context, http);

        // Discovery makes the unauthenticated probe + AS well-known fallback per invocation.
        // After dedup, the second invocation MUST issue zero requests, so total is exactly 2.
        verify(http, times(2)).sendRequest(any(HttpRequest.class));
    }

    @Test
    void does_not_dedup_when_probe_sequence_had_http_layer_error() {
        // Discovery's network probes all return null responses (network failure). The
        // host MUST NOT be claimed — a retry should get a fresh attempt.
        HttpRequestResponse nullResponse = mock(HttpRequestResponse.class);
        lenient().when(nullResponse.response()).thenReturn(null);
        when(http.sendRequest(any(HttpRequest.class))).thenReturn(nullResponse);

        check.runOnceForSession(context, http);
        check.runOnceForSession(context, http);

        // With null responses, discovery makes two requests per invocation (unauth probe
        // + AS well-known fallback) — both invocations probed because the HTTP-layer
        // error path doesn't poison dedup.
        verify(http, times(4)).sendRequest(any(HttpRequest.class));
    }

    @Test
    void disabledInSettings_skipsScanStartProbe() {
        when(settings.isEnabled(anyString(), anyBoolean())).thenReturn(false);

        List<AuditIssue> issues = check.runOnceForSession(context, http);

        assertThat(issues).isEmpty();
        verify(http, never()).sendRequest(any(HttpRequest.class));
    }

    @Test
    void isNotARegisteredPerRequestActiveScanCheck() {
        // The double-report fix: this check now runs ONLY at scan-start, so it must not be a
        // Burp per-request ActiveScanCheck (which would fire a second, divergent surface).
        assertThat(check).isNotInstanceOf(ActiveScanCheck.class);
    }

    // ---------- helpers ----------

    private static McpActiveDcrMisconfigurationCheck dcrCheck(ScanCheckSettings settings,
                                                              McpEventLog eventLog) {
        return new McpActiveDcrMisconfigurationCheck(settings,
                new com.mcpscanner.auth.oauth.discovery.BurpAuthorizationServerDiscovery(),
                eventLog,
                new TrackingSessionBaselineFactory());
    }

    private HttpRequestResponse httpRequestResponse(int statusCode, String body) {
        return httpRequestResponseWithHeader(statusCode, null, null, body);
    }

    private HttpRequestResponse httpRequestResponseWithHeader(int statusCode, String headerName, String headerValue,
                                                              String body) {
        HttpRequestResponse rr = mock(HttpRequestResponse.class);
        HttpResponse response = mock(HttpResponse.class);
        lenient().when(rr.response()).thenReturn(response);
        lenient().when(response.statusCode()).thenReturn((short) statusCode);
        lenient().when(response.bodyToString()).thenReturn(body == null ? "" : body);
        if (headerName != null) {
            lenient().when(response.headerValue(headerName)).thenReturn(headerValue);
        }
        return rr;
    }

    private HttpRequestResponse redirectTo(String location) {
        return httpRequestResponseWithHeader(302, "Location", location, "");
    }
}
