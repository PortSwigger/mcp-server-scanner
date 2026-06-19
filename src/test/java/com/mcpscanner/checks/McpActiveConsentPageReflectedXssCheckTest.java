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
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class McpActiveConsentPageReflectedXssCheckTest {

    private static final String ISSUE_NAME = "MCP OAuth Consent Page Reflected XSS";
    private static final String ENDPOINT = "https://mcp.example.com/mcp";

    private static final String AS_BODY = "{\n"
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

    private static final String REGISTERED_CLIENT = "{\"client_id\":\"client-xyz\"}";

    @BeforeAll
    static void installFactory() {
        MontoyaTestFactory.install();
    }

    @Mock private Http http;
    @Mock private ScanCheckSettings settings;

    private McpActiveConsentPageReflectedXssCheck check;
    private final ScanStartContext context = new ScanStartContext(ENDPOINT, Map.of());

    @BeforeEach
    void setUp() {
        lenient().when(settings.isEnabled(anyString(), anyBoolean())).thenReturn(true);
        check = consentCheck(settings, null);
    }

    @Test
    void rawReflectionInScriptIslandNoCsp_firesHighFirm() {
        queue(unauth(), as(AS_BODY), registration(),
                consentReflectingCanary(true, null));

        List<AuditIssue> issues = check.runOnceForSession(context, http);

        assertThat(issues).hasSize(1);
        AuditIssue issue = issues.get(0);
        assertThat(issue.name()).isEqualTo(ISSUE_NAME);
        assertThat(issue.severity()).isEqualTo(AuditIssueSeverity.HIGH);
        assertThat(issue.confidence()).isEqualTo(AuditIssueConfidence.FIRM);
        assertThat(issue.detail()).contains("script");
    }

    @Test
    void rawReflectionInBodyNoCsp_firesHighFirm() {
        queue(unauth(), as(AS_BODY), registration(),
                consentReflectingCanary(false, null));

        List<AuditIssue> issues = check.runOnceForSession(context, http);

        assertThat(issues).hasSize(1);
        AuditIssue issue = issues.get(0);
        assertThat(issue.severity()).isEqualTo(AuditIssueSeverity.HIGH);
        assertThat(issue.confidence()).isEqualTo(AuditIssueConfidence.FIRM);
    }

    @Test
    void rawReflectionWithMitigatingCsp_downgradesToLow() {
        queue(unauth(), as(AS_BODY), registration(),
                consentReflectingCanary(true, "script-src 'self'"));

        List<AuditIssue> issues = check.runOnceForSession(context, http);

        assertThat(issues).hasSize(1);
        AuditIssue issue = issues.get(0);
        assertThat(issue.severity()).isEqualTo(AuditIssueSeverity.LOW);
        assertThat(issue.detail()).contains("CSP");
    }

    @Test
    void entityEncodedReflection_raisesNoIssue() {
        queue(unauth(), as(AS_BODY), registration(),
                consentEntityEncoded());

        List<AuditIssue> issues = check.runOnceForSession(context, http);

        assertThat(issues).isEmpty();
    }

    @Test
    void brokerRedirectToDifferentOrigin_raisesNoIssue() {
        queue(unauth(), as(AS_BODY), registration(),
                redirectTo("https://broker.other-origin.example/consent"));

        List<AuditIssue> issues = check.runOnceForSession(context, http);

        assertThat(issues).isEmpty();
    }

    @Test
    void loginRedirect_raisesNoIssue() {
        // 302 to a same-origin login page that does NOT reflect the canary — no finding.
        queue(unauth(), as(AS_BODY), registration(),
                redirectTo("https://auth.example.com/login?return_to=%2Fauthorize"),
                loginPageWithoutCanary());

        List<AuditIssue> issues = check.runOnceForSession(context, http);

        assertThat(issues).isEmpty();
    }

    @Test
    void sameOriginConsentHopReflectsCanary_firesHigh() {
        queue(unauth(), as(AS_BODY), registration(),
                redirectTo("https://auth.example.com/authorize/consent"),
                consentReflectingCanary(true, null));

        List<AuditIssue> issues = check.runOnceForSession(context, http);

        assertThat(issues).hasSize(1);
        assertThat(issues.get(0).severity()).isEqualTo(AuditIssueSeverity.HIGH);
    }

    @Test
    void registrationCarriesBothLoopbackFormsAndHttpsRedirect() {
        // Blocker 2: the single DCR registration must offer BOTH loopback forms (127.0.0.1 AND
        // localhost — some servers gate on only one) plus the https probe, so /authorize can be
        // driven with each redirect style without re-registering.
        queue(unauth(), as(AS_BODY), registration(),
                consentReflectingCanary(true, null));

        check.runOnceForSession(context, http);

        String registrationBody = sentRequests.get(2).bodyToString();
        assertThat(registrationBody).contains("127.0.0.1");
        assertThat(registrationBody).contains("localhost");
        assertThat(registrationBody).contains("https://");
    }

    @Test
    void inverseTrustGate_reflectsOnlyForHttpsRedirect_firesHigh() {
        // Blocker 2: a server that accepts loopback registration but reflects the canary ONLY when
        // /authorize is driven with the HTTPS redirect (inverse of the loopback trust gate). The check
        // must probe BOTH redirect styles and fire on the https one.
        // Loopback /authorize drives return an escaped (safe) consent page; the https drive reflects.
        queue(unauth(), as(AS_BODY), registration(),
                consentEntityEncoded(),               // 127.0.0.1 drive: escaped
                consentEntityEncoded(),               // localhost drive: escaped
                consentReflectingCanary(true, null)); // https drive: raw breakout

        List<AuditIssue> issues = check.runOnceForSession(context, http);

        assertThat(issues).hasSize(1);
        assertThat(issues.get(0).severity()).isEqualTo(AuditIssueSeverity.HIGH);
    }

    @Test
    void loopbackTrustGate_reflectsOnlyForLoopbackRedirect_firesHigh() {
        // Blocker 2 (forward loopback gate): first redirect style probed (loopback) reflects raw, so the
        // check fires on the FIRST breakout and need not probe the remaining styles.
        queue(unauth(), as(AS_BODY), registration(),
                consentReflectingCanary(true, null)); // first /authorize drive reflects

        List<AuditIssue> issues = check.runOnceForSession(context, http);

        assertThat(issues).hasSize(1);
        assertThat(issues.get(0).severity()).isEqualTo(AuditIssueSeverity.HIGH);
    }

    @Test
    void crossOriginLoginBounceCarryingAsOriginConsentUrl_firesHigh() {
        // Gap 2: /authorize 302s CROSS-ORIGIN to a sign-in page whose postSignUp param holds the
        // real AS-origin consent URL. The check must unwrap it, fetch the AS-origin consent, and fire.
        String loginBounce = "https://login.other-origin.example/signin"
                + "?postSignUp=https%3A%2F%2Fauth.example.com%2Fauthorize%2Fconsent%3Fstate%3Dabc";
        queue(unauth(), as(AS_BODY), registration(),
                redirectTo(loginBounce),
                consentReflectingCanary(true, null));

        List<AuditIssue> issues = check.runOnceForSession(context, http);

        assertThat(issues).hasSize(1);
        assertThat(issues.get(0).severity()).isEqualTo(AuditIssueSeverity.HIGH);
    }

    @Test
    void crossOriginLoginBounceCarryingCrossOriginConsentUrl_raisesNoIssueAndDoesNotFetch() {
        // Gap 2 safety bound: the embedded consent URL is itself cross-origin — HARD REFUSE. The
        // check must not fetch it and must raise nothing (no SSRF/open-fetch primitive).
        String loginBounce = "https://login.other-origin.example/signin"
                + "?postSignUp=https%3A%2F%2Fevil.attacker.example%2Fauthorize%2Fconsent";
        queue(unauth(), as(AS_BODY), registration(),
                redirectTo(loginBounce));

        List<AuditIssue> issues = check.runOnceForSession(context, http);

        assertThat(issues).isEmpty();
        // No consent-fetch follow-up is ever issued: every request is either the unauth probe, AS
        // metadata, registration, or an /authorize drive (each refusing the cross-origin embedded
        // consent URL). The cross-origin consent URL is HARD-REFUSED, never fetched.
        assertThat(sentRequests).noneMatch(req ->
                req.url() != null && req.url().contains("evil.attacker.example"));
    }

    @Test
    void noRegistrationEndpoint_skipsAndLogs() {
        McpEventLog eventLog = mock(McpEventLog.class);
        check = consentCheck(settings, eventLog);
        queue(unauth(), as(AS_BODY_NO_REGISTRATION));

        List<AuditIssue> issues = check.runOnceForSession(context, http);

        assertThat(issues).isEmpty();
        verify(eventLog, atLeastOnce()).info(contains("registration_endpoint"));
    }

    @Test
    void noAuthorizationEndpoint_skipsAndLogs() {
        McpEventLog eventLog = mock(McpEventLog.class);
        check = consentCheck(settings, eventLog);
        queue(unauth(), as(AS_BODY_NO_AUTHORIZE));

        List<AuditIssue> issues = check.runOnceForSession(context, http);

        assertThat(issues).isEmpty();
        verify(eventLog, atLeastOnce()).info(contains("authorization_endpoint"));
    }

    @Test
    void registrationRejected_skipsNoIssue() {
        // DCR rejects the canary client registration (no client_id issued) — nothing to drive.
        HttpRequestResponse rejected = httpRequestResponse(401, "");
        queue(unauth(), as(AS_BODY), rejected);

        List<AuditIssue> issues = check.runOnceForSession(context, http);

        assertThat(issues).isEmpty();
    }

    @Test
    void plantsInertCanaryWithBreakoutButNoExecutablePayload() {
        queue(unauth(), as(AS_BODY), registration(),
                consentReflectingCanary(true, null));

        check.runOnceForSession(context, http);

        String registrationBody = sentRequests.get(2).bodyToString();
        assertThat(registrationBody).contains("mcpxss-canary-");
        assertThat(registrationBody).contains("</script>");
        assertThat(registrationBody.toLowerCase()).doesNotContain("onerror");
        assertThat(registrationBody.toLowerCase()).doesNotContain("onload");
        assertThat(registrationBody.toLowerCase()).doesNotContain("javascript:");
        assertThat(registrationBody).doesNotContain("alert(");
    }

    @Test
    void runsOncePerHost() {
        queue(unauth(), as(AS_BODY_NO_REGISTRATION),
                unauth(), as(AS_BODY_NO_REGISTRATION));

        check.runOnceForSession(context, http);
        check.runOnceForSession(context, http);

        verify(http, org.mockito.Mockito.times(2)).sendRequest(any(HttpRequest.class));
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

    private static McpActiveConsentPageReflectedXssCheck consentCheck(ScanCheckSettings settings,
                                                                      McpEventLog eventLog) {
        return new McpActiveConsentPageReflectedXssCheck(settings,
                new com.mcpscanner.auth.oauth.discovery.BurpAuthorizationServerDiscovery(),
                eventLog,
                new TrackingSessionBaselineFactory());
    }

    private void queue(HttpRequestResponse... responses) {
        java.util.Queue<HttpRequestResponse> queue = new java.util.ArrayDeque<>(List.of(responses));
        HttpRequestResponse last = responses[responses.length - 1];
        when(http.sendRequest(any(HttpRequest.class))).thenAnswer(inv -> {
            sentRequests.add(inv.getArgument(0));
            return queue.isEmpty() ? last : queue.poll();
        });
    }

    private HttpRequestResponse unauth() {
        return httpRequestResponse(401, "");
    }

    private HttpRequestResponse as(String body) {
        return httpRequestResponse(200, body);
    }

    private HttpRequestResponse registration() {
        return httpRequestResponse(201, REGISTERED_CLIENT);
    }

    private HttpRequestResponse consentReflectingCanary(boolean inScript, String csp) {
        // The check plants a runtime-random canary; mirror whatever marker it sends into the
        // consent HTML so RAW survival is detected regardless of the random nonce.
        HttpRequestResponse rr = mock(HttpRequestResponse.class);
        HttpResponse response = mock(HttpResponse.class);
        lenient().when(rr.response()).thenReturn(response);
        lenient().when(response.statusCode()).thenReturn((short) 200);
        lenient().when(response.headerValue("Location")).thenReturn(null);
        lenient().when(response.headerValue("Content-Security-Policy")).thenReturn(csp);
        lenient().when(response.bodyToString()).thenAnswer(inv -> {
            String canary = capturedCanaryMarker();
            if (inScript) {
                return "<html><head><script>var m={\"name\":\"" + canary
                        + "\"};</script></head><body>consent</body></html>";
            }
            return "<html><body><h1>Authorize " + canary + "</h1></body></html>";
        });
        return rr;
    }

    private HttpRequestResponse consentEntityEncoded() {
        HttpRequestResponse rr = mock(HttpRequestResponse.class);
        HttpResponse response = mock(HttpResponse.class);
        lenient().when(rr.response()).thenReturn(response);
        lenient().when(response.statusCode()).thenReturn((short) 200);
        lenient().when(response.bodyToString()).thenAnswer(inv ->
                "<html><body><h1>Authorize "
                        + capturedCanaryMarker().replace("<", "&lt;").replace(">", "&gt;")
                        + "</h1></body></html>");
        return rr;
    }

    private HttpRequestResponse loginPageWithoutCanary() {
        return httpRequestResponse(200, "<html><body>Please sign in</body></html>");
    }

    private final java.util.List<HttpRequest> sentRequests = new java.util.ArrayList<>();

    private String capturedCanaryMarker() {
        // The canary marker tag <mcpxss-canary-NONCE> is planted in the registration body the
        // check sends. Recover it so the consent HTML echoes the exact runtime-random marker.
        for (HttpRequest sent : sentRequests) {
            String body = sent.bodyToString();
            if (body != null && body.contains("<mcpxss-canary-")) {
                int start = body.indexOf("<mcpxss-canary-");
                int end = body.indexOf('>', start);
                if (start >= 0 && end > start) {
                    return body.substring(start, end + 1);
                }
            }
        }
        throw new IllegalStateException("no canary marker found in sent requests");
    }

    private HttpRequestResponse httpRequestResponse(int statusCode, String body) {
        HttpRequestResponse rr = mock(HttpRequestResponse.class);
        HttpResponse response = mock(HttpResponse.class);
        lenient().when(rr.response()).thenReturn(response);
        lenient().when(response.statusCode()).thenReturn((short) statusCode);
        lenient().when(response.bodyToString()).thenReturn(body == null ? "" : body);
        return rr;
    }

    private HttpRequestResponse redirectTo(String location) {
        HttpRequestResponse rr = mock(HttpRequestResponse.class);
        HttpResponse response = mock(HttpResponse.class);
        lenient().when(rr.response()).thenReturn(response);
        lenient().when(response.statusCode()).thenReturn((short) 302);
        lenient().when(response.headerValue("Location")).thenReturn(location);
        lenient().when(response.bodyToString()).thenReturn("");
        return rr;
    }
}
