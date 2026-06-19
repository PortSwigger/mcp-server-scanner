package com.mcpscanner.checks;

import burp.api.montoya.http.Http;
import burp.api.montoya.http.HttpService;
import burp.api.montoya.http.message.HttpHeader;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.api.montoya.scanner.AuditResult;
import burp.api.montoya.scanner.audit.insertionpoint.AuditInsertionPoint;
import burp.api.montoya.scanner.audit.issues.AuditIssue;
import burp.api.montoya.scanner.audit.issues.AuditIssueConfidence;
import burp.api.montoya.scanner.audit.issues.AuditIssueSeverity;
import burp.api.montoya.scanner.scancheck.ScanCheckType;
import com.mcpscanner.auth.AuthStrategy;
import com.mcpscanner.auth.CustomHeaderAuthStrategy;
import com.mcpscanner.auth.NoAuthStrategy;
import com.mcpscanner.checks.registry.CheckDescriptor;
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

import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;
import java.util.function.Supplier;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyBoolean;
import static org.mockito.ArgumentMatchers.anyList;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.ArgumentMatchers.contains;
import static org.mockito.Mockito.atLeastOnce;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class McpActiveOAuthTokenValidationCheckTest {

    private static final String SUCCESS_BODY = "{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{}}";
    private static final String ERROR_BODY = "{\"jsonrpc\":\"2.0\",\"id\":1,\"error\":{\"code\":-32600}}";
    private static final String TOOL_IS_ERROR_BODY =
            "{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{\"content\":[{\"type\":\"text\",\"text\":\"invalid\"}],\"isError\":true}}";
    private static final String VALID_JWT = buildJwt(
            "{\"alg\":\"RS256\",\"typ\":\"JWT\"}",
            "{\"aud\":\"https://server.example/mcp\",\"iss\":\"https://issuer.example/\",\"sub\":\"user\"}");

    @BeforeAll
    static void installFactory() {
        MontoyaTestFactory.install();
    }

    @Mock private HttpRequestResponse baseRequestResponse;
    @Mock private AuditInsertionPoint insertionPoint;
    @Mock private Http http;
    @Mock private HttpRequest request;
    @Mock private HttpRequest strippedRequest;
    @Mock private HttpRequest stripSentinelRequest;
    @Mock private HttpRequest mutatedRequest;
    @Mock private HttpService httpService;
    @Mock private ScanCheckSettings settings;

    private McpActiveOAuthTokenValidationCheck check;

    @BeforeEach
    void setUp() {
        lenient().when(settings.isEnabled(anyString(), anyBoolean())).thenReturn(true);
        check = new McpActiveOAuthTokenValidationCheck(settings, NoAuthStrategy::new);
    }

    @Test
    void descriptor_exposesOAuthTokenValidationMetadata() {
        CheckDescriptor descriptor = check.descriptor();

        assertThat(descriptor.id()).isEqualTo("oauth-token-validation");
        assertThat(descriptor.displayName()).isEqualTo("MCP OAuth Token Validation");
        assertThat(descriptor.headlineSeverity()).isEqualTo(AuditIssueSeverity.HIGH);
        assertThat(descriptor.scope()).isEqualTo(ScanCheckType.PER_HOST);
        assertThat(descriptor.defaultEnabled()).isTrue();
        // Vuln-first description: drop the "Mints attacker-signed JWTs ... then checks" mechanics.
        assertThat(descriptor.description()).doesNotStartWith("Mints");
        assertThat(descriptor.description()).doesNotContain("Mints attacker-signed");
        // Trimmed references: cut RFC8707 and the Aaron Parecki blog.
        assertThat(descriptor.references()).containsExactly(
                "https://modelcontextprotocol.io/specification/2025-11-25/basic/authorization#access-token-privilege-restriction",
                "https://datatracker.ietf.org/doc/html/rfc9068",
                "https://datatracker.ietf.org/doc/html/rfc8725",
                "https://datatracker.ietf.org/doc/html/rfc9700#section-2.3",
                "https://portswigger.net/web-security/jwt");
    }

    @Test
    void doCheck_returnsEmptyWhenDisabled() {
        when(settings.isEnabled("oauth-token-validation", true)).thenReturn(false);

        AuditResult result = check.doCheck(baseRequestResponse, insertionPoint, http);

        assertThat(result.auditIssues()).isEmpty();
        verify(http, never()).sendRequest(any(HttpRequest.class));
    }

    @Test
    void skipsNonMcpBaseline() {
        when(baseRequestResponse.request()).thenReturn(request);
        when(request.method()).thenReturn("POST");
        when(request.bodyToString()).thenReturn("{\"hello\":\"world\"}");

        AuditResult result = check.doCheck(baseRequestResponse, insertionPoint, http);

        assertThat(result.auditIssues()).isEmpty();
        verify(http, never()).sendRequest(any(HttpRequest.class));
    }

    @Test
    void skipsWhenAuthorizationIsOpaqueToken() {
        stubMcpRequestWithAuth("Bearer opaque-not-jwt-token");

        AuditResult result = check.doCheck(baseRequestResponse, insertionPoint, http);

        assertThat(result.auditIssues()).isEmpty();
        verify(http, never()).sendRequest(any(HttpRequest.class));
    }

    @Test
    void skipsWhenNoAuthorizationHeader() {
        stubMcpRequestWithAuth(null);

        AuditResult result = check.doCheck(baseRequestResponse, insertionPoint, http);

        assertThat(result.auditIssues()).isEmpty();
        verify(http, never()).sendRequest(any(HttpRequest.class));
    }

    @Test
    void engages_onResourcesReadBaseline() {
        stubMcpRequestWithBodyAndAuth(
                "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"resources/read\",\"params\":{\"uri\":\"file:///x\"}}",
                "Bearer " + VALID_JWT);
        stubAllProbesSucceed();

        AuditResult result = check.doCheck(baseRequestResponse, insertionPoint, http);

        assertThat(bundledIssue(result).detail()).contains("Signature validation weakness");
    }

    @Test
    void engages_onPromptsGetBaseline() {
        stubMcpRequestWithBodyAndAuth(
                "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"prompts/get\",\"params\":{\"name\":\"p\"}}",
                "Bearer " + VALID_JWT);
        stubAllProbesSucceed();

        AuditResult result = check.doCheck(baseRequestResponse, insertionPoint, http);

        assertThat(bundledIssue(result).detail()).contains("Signature validation weakness");
    }

    @Test
    void returnsEmptyWhenAllProbeResponsesHaveResultIsErrorTrue() {
        stubMcpRequestWithAuth("Bearer " + VALID_JWT);
        HttpRequestResponse toolError = httpRequestResponse(200, TOOL_IS_ERROR_BODY);
        when(http.sendRequest(any(HttpRequest.class))).thenReturn(toolError);

        AuditResult result = check.doCheck(baseRequestResponse, insertionPoint, http);

        assertThat(result.auditIssues()).isEmpty();
    }

    @Test
    void firesSignatureWeaknessSectionWhenRandomSigProbeSucceeds() {
        stubMcpRequestWithAuth("Bearer " + VALID_JWT);
        stubAllProbesSucceed();

        AuditResult result = check.doCheck(baseRequestResponse, insertionPoint, http);

        assertThat(bundledIssue(result).detail()).contains("Signature validation weakness");
    }

    @Test
    void wrongAudSuccessIsFramedAsAttackerMintedTokenAcceptanceNotAudienceValidationSkipped() {
        stubTrackingMcpRequest(Map.of("Authorization", "Bearer " + VALID_JWT));
        // 5 probes: RANDOM_SIG, WRONG_AUD, WRONG_ISS, EXPIRED, ALG_NONE
        stubProbeContentAware(false, true, false, false, false);

        AuditResult result = check.doCheck(baseRequestResponse, insertionPoint, http);

        String detail = singleOAuthIssue(result).detail();
        assertThat(detail).contains("Attacker-minted token accepted");
        assertThat(detail).contains("attacker-controlled audience");
        assertThat(detail).doesNotContain("Audience validation skipped",
                "Signature validation skipped",
                "Issuer validation skipped",
                "Expired token accepted",
                "alg:none token accepted");
        assertThat(detail).doesNotContain("attacker-controlled issuer");
        assertThat(detail).doesNotContain("(expired)");
    }

    @Test
    void wrongIssSuccessIsFramedAsAttackerMintedTokenAcceptanceNotIssuerValidationSkipped() {
        stubTrackingMcpRequest(Map.of("Authorization", "Bearer " + VALID_JWT));
        stubProbeContentAware(false, false, true, false, false);

        AuditResult result = check.doCheck(baseRequestResponse, insertionPoint, http);

        String detail = singleOAuthIssue(result).detail();
        assertThat(detail).contains("Attacker-minted token accepted");
        assertThat(detail).contains("attacker-controlled issuer");
        assertThat(detail).doesNotContain("Issuer validation skipped",
                "Audience validation skipped",
                "Expired token accepted",
                "alg:none token accepted");
        assertThat(detail).doesNotContain("attacker-controlled audience");
        assertThat(detail).doesNotContain("(expired)");
    }

    @Test
    void expiredSuccessIsFramedAsAttackerMintedTokenAcceptanceNotExpiryValidationSkipped() {
        stubTrackingMcpRequest(Map.of("Authorization", "Bearer " + VALID_JWT));
        stubProbeContentAware(false, false, false, true, false);

        AuditResult result = check.doCheck(baseRequestResponse, insertionPoint, http);

        String detail = singleOAuthIssue(result).detail();
        assertThat(detail).contains("Attacker-minted token accepted");
        assertThat(detail).contains("expired");
        assertThat(detail).doesNotContain("Expired token accepted",
                "Audience validation skipped",
                "Issuer validation skipped",
                "alg:none token accepted");
        assertThat(detail).doesNotContain("attacker-controlled audience");
        assertThat(detail).doesNotContain("attacker-controlled issuer");
    }

    @Test
    void randomSigSuccessDetailLeadsWithSignatureValidationWeakness() {
        stubTrackingMcpRequest(Map.of("Authorization", "Bearer " + VALID_JWT));
        stubProbeContentAware(true, false, false, false, false);

        AuditResult result = check.doCheck(baseRequestResponse, insertionPoint, http);

        String detail = singleOAuthIssue(result).detail();
        assertThat(detail).contains("Signature validation weakness");
        // Internal probe-label dump and inline CVE name-drop are gone.
        assertThat(detail).doesNotContain("Probes that succeeded");
        assertThat(detail).doesNotContain("CVE-2026-44428");
        assertThat(detail).doesNotContain("RANDOM_SIG");
    }

    @Test
    void firesAlgNoneSectionWhenOnlyAlgNoneProbeSucceeds() {
        stubTrackingMcpRequest(Map.of("Authorization", "Bearer " + VALID_JWT));
        stubProbeContentAware(false, false, false, false, true);

        AuditResult result = check.doCheck(baseRequestResponse, insertionPoint, http);

        assertThat(result.auditIssues()).hasSize(1);
        AuditIssue issue = result.auditIssues().get(0);
        assertThat(issue.name()).isEqualTo("MCP OAuth alg:none Token Accepted");
        assertThat(issue.severity()).isEqualTo(AuditIssueSeverity.HIGH);
        assertThat(issue.detail()).contains("alg:none");
        assertThat(issue.remediation()).contains("alg:none");
        // Grammar fix: finding-first complete sentence, no dangling "class alg:none acceptance as".
        assertThat(issue.detail()).doesNotContain("class alg:none acceptance as");
        // Inline CVE name-drops removed from prose.
        assertThat(issue.detail()).doesNotContain("CVE-2026-44428");
        assertThat(issue.detail()).doesNotContain("CVE-2015-9235");
    }

    @Test
    void algNoneAcceptedEmitsOwnHighIssueWithDistinctName() {
        stubTrackingMcpRequest(Map.of("Authorization", "Bearer " + VALID_JWT));
        stubProbeContentAware(false, false, false, false, true);

        AuditResult result = check.doCheck(baseRequestResponse, insertionPoint, http);

        assertThat(result.auditIssues())
                .extracting(AuditIssue::name)
                .containsExactly("MCP OAuth alg:none Token Accepted");
        assertThat(result.auditIssues().get(0).severity()).isEqualTo(AuditIssueSeverity.HIGH);
        assertThat(result.auditIssues().get(0).remediation()).contains("alg:none");
    }

    @Test
    void randomSigPlusAlgNoneEmitsTwoIssues() {
        stubTrackingMcpRequest(Map.of("Authorization", "Bearer " + VALID_JWT));
        // RANDOM_SIG + ALG_NONE both succeed, claim probes short-circuited.
        // Use content-aware stub to correctly separate alg:none from signed probes.
        stubServerAcceptingSignedJwtsAndAlgNone();

        AuditResult result = check.doCheck(baseRequestResponse, insertionPoint, http);

        assertThat(result.auditIssues())
                .extracting(AuditIssue::name)
                .containsExactlyInAnyOrder(
                        "MCP OAuth Token Validation",
                        "MCP OAuth alg:none Token Accepted");
    }

    @Test
    void bundledIssueDoesNotContainAlgNoneSectionWhenSplitOut() {
        stubTrackingMcpRequest(Map.of("Authorization", "Bearer " + VALID_JWT));
        stubProbeContentAware(true, true, true, true, true);

        AuditResult result = check.doCheck(baseRequestResponse, insertionPoint, http);

        AuditIssue bundled = result.auditIssues().stream()
                .filter(i -> i.name().equals("MCP OAuth Token Validation"))
                .findFirst()
                .orElseThrow();
        assertThat(bundled.detail()).doesNotContain("alg:none token accepted");
    }

    @Test
    void suppressesClaimSectionsWhenRandomSigSucceeded() {
        stubTrackingMcpRequest(Map.of("Authorization", "Bearer " + VALID_JWT));
        // All signed probes succeed, alg:none fails.
        // Use content-aware stub because RANDOM_SIG short-circuit changes the number of requests sent.
        stubServerAcceptingSignedJwtsRejectingAlgNone();

        AuditResult result = check.doCheck(baseRequestResponse, insertionPoint, http);

        String detail = singleOAuthIssue(result).detail();
        assertThat(detail).contains("Signature validation weakness");
        assertThat(detail).doesNotContain("attacker-controlled audience",
                "attacker-controlled issuer",
                "Audience validation skipped",
                "Issuer validation skipped",
                "Expired token accepted");
    }

    @Test
    void emitsIndependentSectionsWhenRandomSigFailsButClaimProbesSucceed() {
        stubTrackingMcpRequest(Map.of("Authorization", "Bearer " + VALID_JWT));
        stubProbeContentAware(false, true, true, true, false);

        AuditResult result = check.doCheck(baseRequestResponse, insertionPoint, http);

        String detail = singleOAuthIssue(result).detail();
        assertThat(detail).contains("attacker-controlled audience",
                "attacker-controlled issuer",
                "expired");
        assertThat(detail).doesNotContain("Signature validation weakness",
                "Signature validation skipped",
                "alg:none token accepted");
    }

    @Test
    void emitsAlgNoneAlongsideSignatureSectionWhenBothSucceed() {
        stubTrackingMcpRequest(Map.of("Authorization", "Bearer " + VALID_JWT));
        stubProbeContentAware(true, true, true, true, true);

        AuditResult result = check.doCheck(baseRequestResponse, insertionPoint, http);

        assertThat(result.auditIssues())
                .extracting(AuditIssue::name)
                .containsExactlyInAnyOrder(
                        "MCP OAuth Token Validation",
                        "MCP OAuth alg:none Token Accepted");
        AuditIssue bundled = result.auditIssues().stream()
                .filter(i -> i.name().equals("MCP OAuth Token Validation"))
                .findFirst()
                .orElseThrow();
        assertThat(bundled.detail()).contains("Signature validation weakness");
    }

    @Test
    void remediationMentionsAlgConfusionPrevention() {
        stubTrackingMcpRequest(Map.of("Authorization", "Bearer " + VALID_JWT));
        stubProbeContentAware(false, true, false, false, false);

        AuditResult result = check.doCheck(baseRequestResponse, insertionPoint, http);
        AuditIssue issue = result.auditIssues().get(0);
        assertThat(issue.remediation())
                .contains("verification key type matches the algorithm")
                .contains("algorithm-confusion attacks")
                .contains("RFC 8725 §3.1");
    }

    @Test
    void remediationMentions401AndWwwAuthenticate() {
        stubTrackingMcpRequest(Map.of("Authorization", "Bearer " + VALID_JWT));
        stubProbeContentAware(false, true, false, false, false);

        AuditResult result = check.doCheck(baseRequestResponse, insertionPoint, http);
        AuditIssue issue = result.auditIssues().get(0);
        assertThat(issue.remediation())
                .contains("HTTP 401")
                .contains("WWW-Authenticate: Bearer");
    }

    @Test
    void dedupsRepeatedScansAgainstSameHostAndPath() {
        stubMcpRequestWithAuth("Bearer " + VALID_JWT);
        stubAllProbesSucceed();

        AuditResult first = check.doCheck(baseRequestResponse, insertionPoint, http);
        AuditResult second = check.doCheck(baseRequestResponse, insertionPoint, http);

        assertThat(first.auditIssues()).isNotEmpty();
        assertThat(second.auditIssues()).isEmpty();
    }

    @Test
    void firesPerDistinctHost() {
        HostFixture hostA = stubAdditionalHost("host-a.test", 8080, false, "/mcp", "Bearer " + VALID_JWT);
        HostFixture hostB = stubAdditionalHost("host-b.test", 8080, false, "/mcp", "Bearer " + VALID_JWT);
        stubMutationChain(hostA.request());
        stubMutationChain(hostB.request());
        HttpRequestResponse controlFailure = failureResponse();
        HttpRequestResponse probeSuccess = successResponse();
        lenient().when(http.sendRequest(stripSentinelRequest)).thenReturn(controlFailure);
        when(http.sendRequest(mutatedRequest)).thenReturn(probeSuccess);

        AuditResult firstResult = check.doCheck(hostA.requestResponse(), insertionPoint, http);
        AuditResult secondResult = check.doCheck(hostB.requestResponse(), insertionPoint, http);

        assertThat(firstResult.auditIssues()).isNotEmpty();
        assertThat(secondResult.auditIssues()).isNotEmpty();
    }

    @Test
    void firesPerDistinctPathPrefixOnSameHost() {
        HostFixture pathA = stubAdditionalHost("shared.test", 8080, false, "/alpha/mcp", "Bearer " + VALID_JWT);
        HostFixture pathB = stubAdditionalHost("shared.test", 8080, false, "/beta/mcp", "Bearer " + VALID_JWT);
        stubMutationChain(pathA.request());
        stubMutationChain(pathB.request());
        HttpRequestResponse controlFailure = failureResponse();
        HttpRequestResponse probeSuccess = successResponse();
        lenient().when(http.sendRequest(stripSentinelRequest)).thenReturn(controlFailure);
        when(http.sendRequest(mutatedRequest)).thenReturn(probeSuccess);

        AuditResult firstResult = check.doCheck(pathA.requestResponse(), insertionPoint, http);
        AuditResult secondResult = check.doCheck(pathB.requestResponse(), insertionPoint, http);

        assertThat(firstResult.auditIssues()).isNotEmpty();
        assertThat(secondResult.auditIssues()).isNotEmpty();
    }

    @Test
    void treatsPathCaseAsDistinctForDedup() {
        HostFixture pathLower = stubAdditionalHost("shared.test", 8080, false, "/mcp", "Bearer " + VALID_JWT);
        HostFixture pathUpper = stubAdditionalHost("shared.test", 8080, false, "/MCP", "Bearer " + VALID_JWT);
        stubMutationChain(pathLower.request());
        stubMutationChain(pathUpper.request());
        HttpRequestResponse controlFailure = failureResponse();
        HttpRequestResponse probeSuccess = successResponse();
        lenient().when(http.sendRequest(stripSentinelRequest)).thenReturn(controlFailure);
        when(http.sendRequest(mutatedRequest)).thenReturn(probeSuccess);

        AuditResult firstResult = check.doCheck(pathLower.requestResponse(), insertionPoint, http);
        AuditResult secondResult = check.doCheck(pathUpper.requestResponse(), insertionPoint, http);

        assertThat(firstResult.auditIssues()).isNotEmpty();
        assertThat(secondResult.auditIssues()).isNotEmpty();
    }

    @Test
    void noFalsePositiveWhenServerAcceptsAnySessionBoundRequest() {
        check = new McpActiveOAuthTokenValidationCheck(settings, NoAuthStrategy::new);
        stubTrackingMcpRequest(Map.of(
                "Authorization", "Bearer " + VALID_JWT,
                "Mcp-Session-Id", "sess-123"));
        stubServerRequiringSurvivingHeader("Mcp-Session-Id");

        AuditResult result = check.doCheck(baseRequestResponse, insertionPoint, http);

        assertThat(result.auditIssues()).isEmpty();
    }

    @Test
    void noFalsePositiveAgainstCookieAuthedServerWhenInvalidJwtSubmitted() {
        check = new McpActiveOAuthTokenValidationCheck(settings, NoAuthStrategy::new);
        stubTrackingMcpRequest(Map.of(
                "Authorization", "Bearer " + VALID_JWT,
                "Cookie", "session=abc"));
        stubServerRequiringSurvivingHeader("Cookie");

        AuditResult result = check.doCheck(baseRequestResponse, insertionPoint, http);

        assertThat(result.auditIssues()).isEmpty();
    }

    @Test
    void noFalsePositiveAgainstWildcardAcceptServer() {
        check = new McpActiveOAuthTokenValidationCheck(settings, NoAuthStrategy::new);
        stubTrackingMcpRequest(Map.of(
                "Authorization", "Bearer " + VALID_JWT));
        stubServerAcceptingEveryRequest();

        AuditResult result = check.doCheck(baseRequestResponse, insertionPoint, http);

        assertThat(result.auditIssues()).isEmpty();
    }

    @Test
    void noFalsePositiveAgainstCustomHeaderAuthServer() {
        Supplier<AuthStrategy> customAuth = () -> new CustomHeaderAuthStrategy(Map.of("X-Api-Key", "abc"));
        check = new McpActiveOAuthTokenValidationCheck(settings, customAuth);
        stubTrackingMcpRequest(Map.of(
                "Authorization", "Bearer " + VALID_JWT,
                "X-Api-Key", "abc"));
        stubServerRequiringSurvivingHeader("X-Api-Key");

        AuditResult result = check.doCheck(baseRequestResponse, insertionPoint, http);

        assertThat(result.auditIssues()).isEmpty();
    }

    @Test
    void firesFinding_whenSessionBoundServerHasBrokenJwtValidation() {
        // Server requires BOTH Mcp-Session-Id AND a JWT-shaped Authorization bearer:
        //  - Missing session    -> failure (regardless of auth).
        //  - Session present + non-JWT bearer (garbage)    -> failure.
        //  - Session present + JWT-shaped bearer (any signature) -> success (broken JWT validation).
        // Current implementation strips Mcp-Session-Id along with Authorization on every probe,
        // so every probe lands at the server with no session and is rejected -> no issue (FN).
        // Post-fix probes preserve Mcp-Session-Id; the attacker-signed JWT probes succeed and
        // the garbage-bearer dominance check stays clear, so a FIRM issue is emitted.
        check = new McpActiveOAuthTokenValidationCheck(settings, NoAuthStrategy::new);
        stubTrackingMcpRequest(Map.of(
                "Authorization", "Bearer " + VALID_JWT,
                "Mcp-Session-Id", "sess-123"));
        stubSessionBoundServerWithBrokenJwtValidation();

        AuditResult result = check.doCheck(baseRequestResponse, insertionPoint, http);

        assertThat(result.auditIssues())
                .extracting(AuditIssue::name)
                .contains("MCP OAuth Token Validation");
    }

    private void stubSessionBoundServerWithBrokenJwtValidation() {
        when(http.sendRequest(any(HttpRequest.class))).thenAnswer(invocation -> {
            HttpRequest sent = invocation.getArgument(0);
            String session = sent.headerValue("Mcp-Session-Id");
            if (session == null || session.isEmpty()) {
                return failureResponse();
            }
            String auth = sent.headerValue("Authorization");
            if (auth == null || auth.isEmpty()) {
                return failureResponse();
            }
            return looksLikeJwt(auth) ? successResponse() : failureResponse();
        });
    }

    // ---------- Differential auth-bypass / JWT-validation interaction (Task 1) ----------

    @Test
    void skips_jwt_probes_when_garbage_bearer_also_accepted() {
        McpEventLog eventLog = mock(McpEventLog.class);
        check = new McpActiveOAuthTokenValidationCheck(settings, NoAuthStrategy::new, eventLog);
        stubTrackingMcpRequest(Map.of("Authorization", "Bearer " + VALID_JWT));
        stubServerAcceptingEveryRequest();

        AuditResult result = check.doCheck(baseRequestResponse, insertionPoint, http);

        assertThat(result.auditIssues()).isEmpty();
        verify(eventLog, atLeastOnce()).info(contains("decision: skipped"));
        verify(eventLog, atLeastOnce()).info(contains("auth bypass dominates"));
    }

    @Test
    void emits_signature_skip_tentative_when_server_accepts_no_auth_but_rejects_garbage_bearer() {
        stubTrackingMcpRequest(Map.of("Authorization", "Bearer " + VALID_JWT));
        stubServerRejectingOnlyGarbageBearer();

        AuditResult result = check.doCheck(baseRequestResponse, insertionPoint, http);

        AuditIssue issue = bundledIssue(result);
        assertThat(issue.detail()).contains("Signature validation weakness");
        assertThat(issue.confidence()).isEqualTo(AuditIssueConfidence.TENTATIVE);
        assertThat(issue.detail()).containsIgnoringCase("auth bypass");
        // Tightened note: drop the mechanical "same 200 OK as the attacker-signed probe" narration.
        assertThat(issue.detail()).doesNotContain("same 200 OK as the attacker-signed probe");
    }

    @Test
    void still_emits_firm_finding_when_server_requires_bearer_but_validates_badly() {
        stubTrackingMcpRequest(Map.of("Authorization", "Bearer " + VALID_JWT));
        stubServerAcceptingOnlyAnyBearer();

        AuditResult result = check.doCheck(baseRequestResponse, insertionPoint, http);

        AuditIssue issue = bundledIssue(result);
        assertThat(issue.detail()).contains("Signature validation weakness");
        assertThat(issue.confidence()).isEqualTo(AuditIssueConfidence.FIRM);
    }

    @Test
    void emits_no_finding_when_server_correctly_validates_jwts() {
        stubTrackingMcpRequest(Map.of("Authorization", "Bearer " + VALID_JWT));
        stubServerRejectingEveryRequest();

        AuditResult result = check.doCheck(baseRequestResponse, insertionPoint, http);

        assertThat(result.auditIssues()).isEmpty();
    }

    @Test
    void emits_tentative_alg_none_when_only_alg_none_succeeds_under_auth_bypass() {
        stubTrackingMcpRequest(Map.of("Authorization", "Bearer " + VALID_JWT));
        stubServerAcceptingOnlyAlgNoneUnderAuthBypass();

        AuditResult result = check.doCheck(baseRequestResponse, insertionPoint, http);

        AuditIssue issue = singleAlgNoneIssue(result);
        assertThat(issue.confidence()).isEqualTo(AuditIssueConfidence.TENTATIVE);
        assertThat(issue.detail()).containsIgnoringCase("auth bypass");
    }

    @Test
    void emits_tentative_wrong_audience_when_only_wrong_aud_succeeds_under_auth_bypass() {
        stubTrackingMcpRequest(Map.of("Authorization", "Bearer " + VALID_JWT));
        stubServerAcceptingOnlyJwtProbeUnderAuthBypass("WRONG_AUD");

        AuditResult result = check.doCheck(baseRequestResponse, insertionPoint, http);

        AuditIssue issue = bundledIssue(result);
        assertThat(issue.confidence()).isEqualTo(AuditIssueConfidence.TENTATIVE);
        assertThat(issue.detail()).contains("attacker-controlled audience");
        assertThat(issue.detail()).containsIgnoringCase("auth bypass");
    }

    @Test
    void emits_tentative_wrong_issuer_when_only_wrong_iss_succeeds_under_auth_bypass() {
        stubTrackingMcpRequest(Map.of("Authorization", "Bearer " + VALID_JWT));
        stubServerAcceptingOnlyJwtProbeUnderAuthBypass("WRONG_ISS");

        AuditResult result = check.doCheck(baseRequestResponse, insertionPoint, http);

        AuditIssue issue = bundledIssue(result);
        assertThat(issue.confidence()).isEqualTo(AuditIssueConfidence.TENTATIVE);
        assertThat(issue.detail()).contains("attacker-controlled issuer");
    }

    @Test
    void emits_tentative_expired_when_only_expired_succeeds_under_auth_bypass() {
        stubTrackingMcpRequest(Map.of("Authorization", "Bearer " + VALID_JWT));
        stubServerAcceptingOnlyJwtProbeUnderAuthBypass("EXPIRED");

        AuditResult result = check.doCheck(baseRequestResponse, insertionPoint, http);

        AuditIssue issue = bundledIssue(result);
        assertThat(issue.confidence()).isEqualTo(AuditIssueConfidence.TENTATIVE);
        assertThat(issue.detail()).contains("expired");
    }

    // ---------- Item 10: JWT bundling behaviour ----------

    @Test
    void bundledIssue_singleSignatureWeaknessIssue_whenRandomSigSucceeds() {
        stubTrackingMcpRequest(Map.of("Authorization", "Bearer " + VALID_JWT));
        // RANDOM_SIG succeeds and short-circuits remaining claim probes.
        // Expect exactly ONE bundled issue (signature-weakness section); alg:none fails.
        stubServerAcceptingSignedJwtsRejectingAlgNone();

        AuditResult result = check.doCheck(baseRequestResponse, insertionPoint, http);

        assertThat(result.auditIssues()).hasSize(1);
        AuditIssue issue = result.auditIssues().get(0);
        assertThat(issue.name()).isEqualTo("MCP OAuth Token Validation");
        assertThat(issue.detail()).contains("Signature validation weakness");
    }

    @Test
    void bundledIssue_emittedWhenMultipleClaimProbesSucceedWithoutRandomSig() {
        stubTrackingMcpRequest(Map.of("Authorization", "Bearer " + VALID_JWT));
        // RANDOM_SIG rejected (404/401-equivalent), but WRONG_AUD, WRONG_ISS, and EXPIRED all accepted.
        // Expect exactly ONE bundled issue with BUNDLED_HEADLINE and all three claim variants listed.
        stubServerRejectingRandomSigButAcceptingClaimProbes();

        AuditResult result = check.doCheck(baseRequestResponse, insertionPoint, http);

        assertThat(result.auditIssues()).hasSize(1);
        AuditIssue issue = result.auditIssues().get(0);
        assertThat(issue.name()).isEqualTo("MCP OAuth Token Validation");
        assertThat(issue.severity()).isEqualTo(AuditIssueSeverity.HIGH);
        assertThat(issue.confidence()).isEqualTo(AuditIssueConfidence.FIRM);
        assertThat(issue.detail()).contains(
                "Server accepts JWT access tokens with multiple invalid claims");
        assertThat(issue.detail()).contains("attacker-controlled audience");
        assertThat(issue.detail()).contains("attacker-controlled issuer");
        assertThat(issue.detail()).contains("expired");
    }

    @Test
    void perProbeIssue_emittedWhenSingleProbeSucceeds() {
        stubTrackingMcpRequest(Map.of("Authorization", "Bearer " + VALID_JWT));
        // Only WRONG_AUD succeeds; RANDOM_SIG, WRONG_ISS, EXPIRED, ALG_NONE all fail.
        stubProbeContentAware(false, true, false, false, false);

        AuditResult result = check.doCheck(baseRequestResponse, insertionPoint, http);

        assertThat(result.auditIssues()).hasSize(1);
        AuditIssue issue = result.auditIssues().get(0);
        assertThat(issue.name()).isEqualTo("MCP OAuth Token Validation");
        // Single-probe path: per-probe section format (bold heading + detail paragraph).
        assertThat(issue.detail()).contains("Attacker-minted token accepted (attacker-controlled audience)");
        assertThat(issue.detail()).doesNotContain("likely signature validation broken");
    }

    @Test
    void randomSigShortCircuit_stillFires() {
        stubTrackingMcpRequest(Map.of("Authorization", "Bearer " + VALID_JWT));
        // RANDOM_SIG succeeds; remaining signed probes are short-circuited.
        // ALG_NONE fails.
        stubProbeContentAware(true, false, false, false, false);

        AuditResult result = check.doCheck(baseRequestResponse, insertionPoint, http);

        assertThat(result.auditIssues()).hasSize(1);
        AuditIssue issue = result.auditIssues().get(0);
        assertThat(issue.name()).isEqualTo("MCP OAuth Token Validation");
        assertThat(issue.detail()).contains("Signature validation weakness");
    }

    private void stubServerRejectingOnlyGarbageBearer() {
        // 200 OK on no-auth (stripped), 200 OK on JWT-shaped probes, 401 on garbage bearer.
        when(http.sendRequest(any(HttpRequest.class))).thenAnswer(invocation -> {
            HttpRequest sent = invocation.getArgument(0);
            String auth = sent.headerValue("Authorization");
            if (auth != null && !auth.isEmpty() && !looksLikeJwt(auth)) {
                return failureResponse();
            }
            return successResponse();
        });
    }

    private void stubServerAcceptingOnlyAnyBearer() {
        // 401 on no-auth, 200 OK on anything carrying an Authorization header (broken server validates badly).
        when(http.sendRequest(any(HttpRequest.class))).thenAnswer(invocation -> {
            HttpRequest sent = invocation.getArgument(0);
            String auth = sent.headerValue("Authorization");
            return (auth != null && !auth.isEmpty()) ? successResponse() : failureResponse();
        });
    }

    private void stubServerRejectingEveryRequest() {
        HttpRequestResponse failure = failureResponse();
        when(http.sendRequest(any(HttpRequest.class))).thenReturn(failure);
    }

    private void stubServerAcceptingOnlyAlgNoneUnderAuthBypass() {
        // Auth bypass present (no-auth accepted), garbage bearer rejected, only alg:none JWT accepted.
        when(http.sendRequest(any(HttpRequest.class))).thenAnswer(invocation -> {
            HttpRequest sent = invocation.getArgument(0);
            String auth = sent.headerValue("Authorization");
            if (auth == null || auth.isEmpty()) {
                return successResponse();
            }
            if (!looksLikeJwt(auth)) {
                return failureResponse();
            }
            return isAlgNoneJwt(auth) ? successResponse() : failureResponse();
        });
    }

    private void stubServerAcceptingOnlyJwtProbeUnderAuthBypass(String probeLabel) {
        // Auth bypass present, garbage rejected, accept only the JWT probe with the named claim shape.
        // The factory mints attacker-controlled audience as "https://attacker.example/mcp",
        // attacker-controlled issuer as "https://attacker.example/", and expiry epoch == 1.
        when(http.sendRequest(any(HttpRequest.class))).thenAnswer(invocation -> {
            HttpRequest sent = invocation.getArgument(0);
            String auth = sent.headerValue("Authorization");
            if (auth == null || auth.isEmpty()) {
                return successResponse();
            }
            if (!looksLikeJwt(auth)) {
                return failureResponse();
            }
            if (isAlgNoneJwt(auth)) {
                return failureResponse();
            }
            String payload = decodeJwtPayload(auth);
            return probeMatches(probeLabel, payload) ? successResponse() : failureResponse();
        });
    }

    private void stubServerAcceptingSignedJwtsRejectingAlgNone() {
        // No-auth rejected, garbage bearer rejected, alg:none rejected, all RS256-signed JWTs accepted.
        // Use content-aware matching so the RANDOM_SIG short-circuit does not affect outcome.
        when(http.sendRequest(any(HttpRequest.class))).thenAnswer(invocation -> {
            HttpRequest sent = invocation.getArgument(0);
            String auth = sent.headerValue("Authorization");
            if (auth == null || auth.isEmpty()) {
                return failureResponse();
            }
            if (!looksLikeJwt(auth)) {
                return failureResponse();
            }
            return isAlgNoneJwt(auth) ? failureResponse() : successResponse();
        });
    }

    private void stubServerRejectingRandomSigButAcceptingClaimProbes() {
        // No-auth rejected, garbage bearer rejected, alg:none rejected.
        // RANDOM_SIG rejected (attacker RSA key, no matching claim deformity).
        // WRONG_AUD, WRONG_ISS, EXPIRED all accepted (server skips claim validation).
        when(http.sendRequest(any(HttpRequest.class))).thenAnswer(invocation -> {
            HttpRequest sent = invocation.getArgument(0);
            String auth = sent.headerValue("Authorization");
            if (auth == null || auth.isEmpty()) {
                return failureResponse();
            }
            if (!looksLikeJwt(auth)) {
                return failureResponse();
            }
            if (isAlgNoneJwt(auth)) {
                return failureResponse();
            }
            String payload = decodeJwtPayload(auth);
            boolean isClaimProbe = probeMatches("WRONG_AUD", payload)
                    || probeMatches("WRONG_ISS", payload)
                    || probeMatches("EXPIRED", payload);
            return isClaimProbe ? successResponse() : failureResponse();
        });
    }

    private void stubServerAcceptingSignedJwtsAndAlgNone() {
        // No-auth rejected, garbage bearer rejected, both RS256-signed JWTs and alg:none accepted.
        // Use content-aware matching so the RANDOM_SIG short-circuit does not affect outcome.
        when(http.sendRequest(any(HttpRequest.class))).thenAnswer(invocation -> {
            HttpRequest sent = invocation.getArgument(0);
            String auth = sent.headerValue("Authorization");
            if (auth == null || auth.isEmpty()) {
                return failureResponse();
            }
            return looksLikeJwt(auth) ? successResponse() : failureResponse();
        });
    }

    private static boolean probeMatches(String probeLabel, String payloadJson) {
        return switch (probeLabel) {
            case "WRONG_AUD" -> payloadJson.contains("\"aud\":\"https://attacker.example/mcp\"")
                    || payloadJson.contains("\"aud\":[\"https://attacker.example/mcp\"]");
            case "WRONG_ISS" -> payloadJson.contains("\"iss\":\"https://attacker.example/\"");
            case "EXPIRED" -> payloadJson.contains("\"exp\":1,") || payloadJson.contains("\"exp\":1}");
            default -> false;
        };
    }

    private static boolean looksLikeJwt(String authorization) {
        if (!authorization.regionMatches(true, 0, "Bearer ", 0, "Bearer ".length())) {
            return false;
        }
        String token = authorization.substring("Bearer ".length()).trim();
        return token.split("\\.").length >= 2 && token.contains(".");
    }

    private static boolean isAlgNoneJwt(String authorization) {
        String token = authorization.substring("Bearer ".length()).trim();
        String[] parts = token.split("\\.", -1);
        if (parts.length < 2) {
            return false;
        }
        try {
            String headerJson = new String(Base64.getUrlDecoder().decode(parts[0]), StandardCharsets.UTF_8);
            return headerJson.contains("\"alg\":\"none\"");
        } catch (IllegalArgumentException e) {
            return false;
        }
    }

    private static String decodeJwtPayload(String authorization) {
        String token = authorization.substring("Bearer ".length()).trim();
        String[] parts = token.split("\\.", -1);
        if (parts.length < 2) {
            return "";
        }
        try {
            return new String(Base64.getUrlDecoder().decode(parts[1]), StandardCharsets.UTF_8);
        } catch (IllegalArgumentException e) {
            return "";
        }
    }

    private static AuditIssue singleAlgNoneIssue(AuditResult result) {
        assertThat(result.auditIssues()).hasSize(1);
        AuditIssue issue = result.auditIssues().get(0);
        assertThat(issue.name()).isEqualTo("MCP OAuth alg:none Token Accepted");
        return issue;
    }

    // ---------- Session-driven entry point (Task 6) ----------

    @Test
    void runOnceForSession_emits_findings_when_session_has_broken_jwt_bearer() {
        check = oauthTokenCheckWithTrackingFactory(settings, NoAuthStrategy::new, null);
        ScanStartContext context = new ScanStartContext("http://example.test:8080/mcp",
                Map.of("Authorization", "Bearer " + VALID_JWT));
        stubServerAcceptingOnlyAnyBearer();

        List<AuditIssue> issues = check.runOnceForSession(context, http);

        assertThat(issues).isNotEmpty();
    }

    @Test
    void runOnceForSession_returns_empty_and_logs_decision_when_session_has_no_bearer() {
        McpEventLog eventLog = mock(McpEventLog.class);
        check = oauthTokenCheckWithTrackingFactory(settings, NoAuthStrategy::new, eventLog);
        ScanStartContext context = new ScanStartContext("http://example.test:8080/mcp", Map.of());

        List<AuditIssue> issues = check.runOnceForSession(context, http);

        assertThat(issues).isEmpty();
        verify(eventLog, atLeastOnce()).info(contains("decision: skipped"));
        verify(http, never()).sendRequest(any(HttpRequest.class));
    }

    @Test
    void runOnceForSession_returns_empty_when_session_bearer_is_opaque_not_jwt() {
        McpEventLog eventLog = mock(McpEventLog.class);
        check = oauthTokenCheckWithTrackingFactory(settings, NoAuthStrategy::new, eventLog);
        ScanStartContext context = new ScanStartContext("http://example.test:8080/mcp",
                Map.of("Authorization", "Bearer opaque-not-jwt"));

        List<AuditIssue> issues = check.runOnceForSession(context, http);

        assertThat(issues).isEmpty();
        verify(eventLog, atLeastOnce()).info(contains("decision: skipped"));
        verify(http, never()).sendRequest(any(HttpRequest.class));
    }

    @Test
    void runOnceForSession_claims_host_so_subsequent_runCheck_returns_empty() {
        check = oauthTokenCheckWithTrackingFactory(settings, NoAuthStrategy::new, null);
        ScanStartContext context = new ScanStartContext("http://example.test:8080/mcp",
                Map.of("Authorization", "Bearer " + VALID_JWT));
        stubServerAcceptingOnlyAnyBearer();

        List<AuditIssue> launcherIssues = check.runOnceForSession(context, http);
        // Now invoke the Burp-driven runCheck against the same host/path with a JWT bearer.
        stubTrackingMcpRequest(Map.of("Authorization", "Bearer " + VALID_JWT));
        AuditResult burpDrivenResult = check.doCheck(baseRequestResponse, insertionPoint, http);

        assertThat(launcherIssues).isNotEmpty();
        assertThat(burpDrivenResult.auditIssues()).isEmpty();
    }

    @Test
    void runOnceForSession_doesNotPoisonDedup_whenSyntheticBaselineLearnsNothing() {
        check = oauthTokenCheckWithTrackingFactory(settings, NoAuthStrategy::new, null);
        ScanStartContext context = new ScanStartContext("http://example.test:8080/mcp",
                Map.of("Authorization", "Bearer " + VALID_JWT));
        // Simulate the realistic scan-start case: the synthetic tool name ("scan-start")
        // doesn't exist, so every probe gets a JSON-RPC error and no signal is produced.
        // The dedup claim must NOT survive — otherwise the real per-request scan against
        // the same host gets short-circuited and a genuine JWT-validation flaw is missed.
        stubServerRejectingUnknownToolButAcceptingAttackerMintedJwtsForRealTool();

        List<AuditIssue> launcherIssues = check.runOnceForSession(context, http);
        assertThat(launcherIssues).isEmpty();

        // Now invoke the Burp-driven runCheck against a real tool on the same host.
        stubTrackingMcpRequest(Map.of("Authorization", "Bearer " + VALID_JWT));
        AuditResult burpDrivenResult = check.doCheck(baseRequestResponse, insertionPoint, http);

        assertThat(burpDrivenResult.auditIssues()).isNotEmpty();
    }

    private void stubServerRejectingUnknownToolButAcceptingAttackerMintedJwtsForRealTool() {
        // Mirrors a realistic vulnerable server: returns JSON-RPC error for the synthetic
        // "scan-start" tool name (no signal), but accepts attacker-signed JWTs against the
        // real "x" tool.
        String unknownToolError =
                "{\"jsonrpc\":\"2.0\",\"id\":1,\"error\":{\"code\":-32602,\"message\":\"tool not found\"}}";
        when(http.sendRequest(any(HttpRequest.class))).thenAnswer(invocation -> {
            HttpRequest sent = invocation.getArgument(0);
            String body = sent.bodyToString();
            if (body != null && body.contains("\"name\":\"scan-start\"")) {
                return httpRequestResponse(200, unknownToolError);
            }
            String auth = sent.headerValue("Authorization");
            return (auth != null && !auth.isEmpty()) ? successResponse() : failureResponse();
        });
    }

    private static McpActiveOAuthTokenValidationCheck oauthTokenCheckWithTrackingFactory(
            ScanCheckSettings settings,
            Supplier<AuthStrategy> authStrategySupplier,
            McpEventLog eventLog) {
        return new McpActiveOAuthTokenValidationCheck(settings, authStrategySupplier, eventLog,
                new TrackingSessionBaselineFactory());
    }

    private void stubTrackingMcpRequest(Map<String, String> headers) {
        HttpRequest trackingRequest = TrackingRequest.from(headers,
                "{\"jsonrpc\":\"2.0\",\"method\":\"tools/call\",\"params\":{\"name\":\"x\",\"arguments\":{}}}",
                "example.test", 8080, false, "/mcp").asHttpRequest();
        when(baseRequestResponse.request()).thenReturn(trackingRequest);
    }

    private void stubServerRequiringSurvivingHeader(String requiredHeaderName) {
        when(http.sendRequest(any(HttpRequest.class))).thenAnswer(invocation -> {
            HttpRequest sent = invocation.getArgument(0);
            String value = sent.headerValue(requiredHeaderName);
            return (value != null && !value.isEmpty()) ? successResponse() : failureResponse();
        });
    }

    private void stubServerAcceptingEveryRequest() {
        HttpRequestResponse wildcardSuccess = successResponse();
        when(http.sendRequest(any(HttpRequest.class))).thenReturn(wildcardSuccess);
    }

    private void stubMcpRequestWithAuth(String authorizationValue) {
        stubMcpRequestWithBodyAndAuth(
                "{\"jsonrpc\":\"2.0\",\"method\":\"tools/call\",\"params\":{\"name\":\"x\",\"arguments\":{}}}",
                authorizationValue);
    }

    private void stubMcpRequestWithBodyAndAuth(String body, String authorizationValue) {
        when(baseRequestResponse.request()).thenReturn(request);
        when(request.method()).thenReturn("POST");
        when(request.bodyToString()).thenReturn(body);
        lenient().when(request.httpService()).thenReturn(httpService);
        lenient().when(httpService.host()).thenReturn("example.test");
        lenient().when(httpService.port()).thenReturn(8080);
        lenient().when(httpService.secure()).thenReturn(false);
        lenient().when(request.pathWithoutQuery()).thenReturn("/mcp");
        lenient().when(request.headerValue(eq("Authorization"))).thenReturn(authorizationValue);
        HttpHeader authHeader = authorizationValue == null ? null : header("Authorization", authorizationValue);
        List<HttpHeader> headers = authorizationValue == null ? List.of() : List.of(authHeader);
        lenient().when(request.headers()).thenReturn(headers);
        stubMutationChain(request);
    }

    private void stubMutationChain(HttpRequest req) {
        lenient().when(req.withRemovedHeaders(anyList())).thenReturn(strippedRequest);
        lenient().when(req.withHeader(anyString(), anyString())).thenReturn(mutatedRequest);
        // The strip-auth control probe applies ONLY the sentinel header so the proxy will not
        // re-inject session auth. A subsequent Authorization override is what turns the stripped
        // request into the JWT probe — so withHeader(Authorization, ...) on the stripped+sentinel
        // request yields mutatedRequest, and withHeader(sentinel, ...) yields stripped+sentinel.
        lenient().when(strippedRequest.withHeader(eq("X-Mcp-Scanner-Strip-Auth"), anyString()))
                .thenReturn(stripSentinelRequest);
        lenient().when(strippedRequest.withHeader(eq("Authorization"), anyString()))
                .thenReturn(mutatedRequest);
        lenient().when(stripSentinelRequest.withHeader(anyString(), anyString())).thenReturn(mutatedRequest);
        lenient().when(mutatedRequest.withHeader(anyString(), anyString())).thenReturn(mutatedRequest);
    }

    private void stubAllProbesSucceed() {
        HttpRequestResponse controlFailure = failureResponse();
        HttpRequestResponse probeSuccess = successResponse();
        lenient().when(http.sendRequest(stripSentinelRequest)).thenReturn(controlFailure);
        when(http.sendRequest(mutatedRequest)).thenReturn(probeSuccess);
    }

    private void stubProbeSequence(boolean... probeSuccesses) {
        HttpRequestResponse controlFailure = failureResponse();
        HttpRequestResponse[] responses = new HttpRequestResponse[probeSuccesses.length];
        for (int i = 0; i < probeSuccesses.length; i++) {
            responses[i] = probeSuccesses[i] ? successResponse() : failureResponse();
        }
        HttpRequestResponse first = responses[0];
        HttpRequestResponse[] rest = java.util.Arrays.copyOfRange(responses, 1, responses.length);
        lenient().when(http.sendRequest(stripSentinelRequest)).thenReturn(controlFailure);
        when(http.sendRequest(mutatedRequest)).thenReturn(first, rest);
    }

    /**
     * Content-aware alternative to {@link #stubProbeSequence}: routes responses by inspecting
     * the actual probe JWT in the Authorization header rather than call-order position.
     * Probe indices: 0=RANDOM_SIG, 1=WRONG_AUD, 2=WRONG_ISS, 3=EXPIRED, 4=ALG_NONE.
     * Requires {@link #stubTrackingMcpRequest} as the baseline (not {@link #stubMcpRequestWithAuth}).
     */
    private void stubProbeContentAware(boolean... probeSuccesses) {
        HttpRequestResponse[] responses = new HttpRequestResponse[probeSuccesses.length];
        for (int i = 0; i < probeSuccesses.length; i++) {
            responses[i] = probeSuccesses[i] ? successResponse() : failureResponse();
        }
        when(http.sendRequest(any(HttpRequest.class))).thenAnswer(invocation -> {
            HttpRequest sent = invocation.getArgument(0);
            String auth = sent.headerValue("Authorization");
            if (auth == null || auth.isEmpty()) {
                return failureResponse();
            }
            if (!looksLikeJwt(auth)) {
                return failureResponse();
            }
            if (isAlgNoneJwt(auth)) {
                return responses[4];
            }
            String payload = decodeJwtPayload(auth);
            if (probeMatches("WRONG_AUD", payload)) {
                return responses[1];
            }
            if (probeMatches("WRONG_ISS", payload)) {
                return responses[2];
            }
            if (probeMatches("EXPIRED", payload)) {
                return responses[3];
            }
            return responses[0];
        });
    }

    private HttpRequestResponse successResponse() {
        return httpRequestResponse(200, SUCCESS_BODY);
    }

    private HttpRequestResponse failureResponse() {
        return httpRequestResponse(200, ERROR_BODY);
    }

    private HttpRequestResponse httpRequestResponse(int statusCode, String body) {
        HttpRequestResponse rr = mock(HttpRequestResponse.class);
        HttpResponse response = mock(HttpResponse.class);
        lenient().when(rr.response()).thenReturn(response);
        lenient().when(response.statusCode()).thenReturn((short) statusCode);
        lenient().when(response.bodyToString()).thenReturn(body);
        lenient().when(response.headerValue("Content-Type")).thenReturn(null);
        return rr;
    }

    private static HttpHeader header(String name, String value) {
        HttpHeader h = mock(HttpHeader.class);
        lenient().when(h.name()).thenReturn(name);
        lenient().when(h.value()).thenReturn(value);
        return h;
    }

    private HostFixture stubAdditionalHost(String host, int port, boolean secure, String path,
                                           String authorizationValue) {
        HttpRequestResponse rr = mock(HttpRequestResponse.class);
        HttpRequest req = mock(HttpRequest.class);
        HttpService service = mock(HttpService.class);
        HttpHeader authHeader = header("Authorization", authorizationValue);
        lenient().when(rr.request()).thenReturn(req);
        lenient().when(req.method()).thenReturn("POST");
        lenient().when(req.bodyToString()).thenReturn(
                "{\"jsonrpc\":\"2.0\",\"method\":\"tools/call\",\"params\":{\"name\":\"x\",\"arguments\":{}}}");
        lenient().when(req.httpService()).thenReturn(service);
        lenient().when(service.host()).thenReturn(host);
        lenient().when(service.port()).thenReturn(port);
        lenient().when(service.secure()).thenReturn(secure);
        lenient().when(req.pathWithoutQuery()).thenReturn(path);
        lenient().when(req.headerValue("Authorization")).thenReturn(authorizationValue);
        lenient().when(req.headers()).thenReturn(List.of(authHeader));
        return new HostFixture(rr, req);
    }

    private record HostFixture(HttpRequestResponse requestResponse, HttpRequest request) {}

    private static final class TrackingRequest {

        private final Map<String, String> headers;
        private final String body;
        private final String host;
        private final int port;
        private final boolean secure;
        private final String path;

        private TrackingRequest(Map<String, String> headers, String body, String host, int port,
                                boolean secure, String path) {
            this.headers = new TreeMap<>(String.CASE_INSENSITIVE_ORDER);
            this.headers.putAll(headers);
            this.body = body;
            this.host = host;
            this.port = port;
            this.secure = secure;
            this.path = path;
        }

        static TrackingRequest from(Map<String, String> headers, String body, String host, int port,
                                    boolean secure, String path) {
            return new TrackingRequest(headers, body, host, port, secure, path);
        }

        HttpRequest asHttpRequest() {
            List<HttpHeader> headerList = new java.util.ArrayList<>();
            for (Map.Entry<String, String> entry : headers.entrySet()) {
                headerList.add(header(entry.getKey(), entry.getValue()));
            }
            HttpService service = mock(HttpService.class);
            lenient().when(service.host()).thenReturn(host);
            lenient().when(service.port()).thenReturn(port);
            lenient().when(service.secure()).thenReturn(secure);
            HttpRequest req = mock(HttpRequest.class);
            lenient().when(req.method()).thenReturn("POST");
            lenient().when(req.bodyToString()).thenReturn(body);
            lenient().when(req.httpService()).thenReturn(service);
            lenient().when(req.pathWithoutQuery()).thenReturn(path);
            lenient().when(req.headers()).thenReturn(headerList);
            lenient().when(req.headerValue(anyString())).thenAnswer(invocation ->
                    headerValueIgnoreCase(invocation.getArgument(0)));
            lenient().when(req.withRemovedHeaders(anyList())).thenAnswer(invocation -> {
                List<HttpHeader> toRemove = invocation.getArgument(0);
                Map<String, String> next = new LinkedHashMap<>(headers);
                for (HttpHeader h : toRemove) {
                    next.keySet().removeIf(existing -> existing.equalsIgnoreCase(h.name()));
                }
                return new TrackingRequest(next, body, host, port, secure, path).asHttpRequest();
            });
            lenient().when(req.withHeader(anyString(), anyString())).thenAnswer(invocation -> {
                Map<String, String> next = new LinkedHashMap<>(headers);
                String name = invocation.getArgument(0);
                next.keySet().removeIf(existing -> existing.equalsIgnoreCase(name));
                next.put(name, invocation.getArgument(1));
                return new TrackingRequest(next, body, host, port, secure, path).asHttpRequest();
            });
            return req;
        }

        private String headerValueIgnoreCase(String name) {
            for (Map.Entry<String, String> entry : headers.entrySet()) {
                if (entry.getKey().equalsIgnoreCase(name)) {
                    return entry.getValue();
                }
            }
            return null;
        }
    }

    private static AuditIssue singleOAuthIssue(AuditResult result) {
        assertThat(result.auditIssues()).hasSize(1);
        AuditIssue issue = result.auditIssues().get(0);
        assertThat(issue.name()).isEqualTo("MCP OAuth Token Validation");
        return issue;
    }

    private static AuditIssue bundledIssue(AuditResult result) {
        return result.auditIssues().stream()
                .filter(i -> i.name().equals("MCP OAuth Token Validation"))
                .findFirst()
                .orElseThrow(() -> new AssertionError(
                        "Expected a bundled 'MCP OAuth Token Validation' issue but got: "
                                + result.auditIssues()));
    }

    private static String buildJwt(String headerJson, String payloadJson) {
        return encode(headerJson) + "." + encode(payloadJson) + ".signature";
    }

    private static String encode(String value) {
        return Base64.getUrlEncoder().withoutPadding()
                .encodeToString(value.getBytes(StandardCharsets.UTF_8));
    }
}
