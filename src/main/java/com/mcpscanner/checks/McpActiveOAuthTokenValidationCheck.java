package com.mcpscanner.checks;

import burp.api.montoya.http.Http;
import burp.api.montoya.http.HttpService;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.scanner.AuditResult;
import burp.api.montoya.scanner.audit.insertionpoint.AuditInsertionPoint;
import burp.api.montoya.scanner.audit.issues.AuditIssue;
import burp.api.montoya.scanner.audit.issues.AuditIssueConfidence;
import burp.api.montoya.scanner.audit.issues.AuditIssueSeverity;
import burp.api.montoya.scanner.scancheck.ScanCheckType;
import com.mcpscanner.auth.AuthStrategy;
import com.mcpscanner.checks.JwtShapeDetector.JwtClaims;
import com.mcpscanner.checks.OAuthJwtProbeFactory.JwtProbe;
import com.mcpscanner.checks.issue.Cwe;
import com.mcpscanner.checks.issue.IssueBodyBuilder;
import com.mcpscanner.checks.issue.IssueMetadataRenderer;
import com.mcpscanner.checks.registry.CheckDescriptor;
import com.mcpscanner.checks.registry.ManagedActiveCheck;
import com.mcpscanner.checks.registry.ScanCheckLogging;
import com.mcpscanner.checks.registry.ScanCheckSettings;
import com.mcpscanner.checks.registry.SessionScopedCheck;
import com.mcpscanner.logging.McpEventLog;
import com.mcpscanner.mcp.HeaderMutation;
import com.mcpscanner.mcp.McpRequestDetector;
import com.mcpscanner.mcp.ScannerSentinels;
import com.mcpscanner.scan.ScanStartCheck;
import com.mcpscanner.scan.ScanStartContext;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.function.Supplier;

public class McpActiveOAuthTokenValidationCheck extends ManagedActiveCheck
        implements ScanStartCheck, SessionScopedCheck {

    private static final String ISSUE_NAME = "MCP OAuth Token Validation";
    private static final String ALG_NONE_ISSUE_NAME = "MCP OAuth alg:none Token Accepted";
    private static final String SECTION_SIGNATURE = "Signature validation weakness";
    private static final String SECTION_WRONG_AUD = "Attacker-minted token accepted (attacker-controlled audience)";
    private static final String SECTION_WRONG_ISS = "Attacker-minted token accepted (attacker-controlled issuer)";
    private static final String SECTION_EXPIRED = "Attacker-minted token accepted (expired)";
    private static final String BUNDLED_HEADLINE =
            "Server accepts JWT access tokens with multiple invalid claims "
                    + "(likely signature validation broken)";

    private static final String AUTHORIZATION_HEADER = "Authorization";
    private static final String BEARER_PREFIX = "Bearer ";
    private static final String GARBAGE_BEARER_PROBE_TOKEN = "not-a-jwt-at-all";
    private static final String AUTH_BYPASS_NOTE =
            "Note: this server also accepts unauthenticated requests (auth bypass), which dominates "
                    + "the user-visible impact. The JWT validation flaw is still real and will "
                    + "surface once authentication is enforced, so it is reported here at lower "
                    + "confidence.";

    private static final CheckDescriptor DESCRIPTOR = new CheckDescriptor(
            "oauth-token-validation",
            ISSUE_NAME,
            "The server accepts JWT access tokens that a correct validator would reject — tokens "
                    + "signed with an untrusted key, or carrying an invalid audience, issuer, or "
                    + "expiry. An attacker can therefore mint a token and authenticate as any "
                    + "principal.",
            AuditIssueSeverity.HIGH,
            ScanCheckType.PER_HOST,
            true,
            List.of(
                    "https://modelcontextprotocol.io/specification/2025-11-25/basic/authorization#access-token-privilege-restriction",
                    "https://datatracker.ietf.org/doc/html/rfc9068",
                    "https://datatracker.ietf.org/doc/html/rfc8725",
                    "https://datatracker.ietf.org/doc/html/rfc9700#section-2.3",
                    "https://portswigger.net/web-security/jwt"
            ),
            "The server accepts tokens it should reject (for example unsigned alg:none JWTs, or "
                    + "tokens failing audience/signature/expiry checks), so token validation is "
                    + "incomplete.",
            List.of(
                    new Cwe(347, "Improper Verification of Cryptographic Signature"),
                    new Cwe(287, "Improper Authentication"))
    );

    private final Set<String> probedKeys = ConcurrentHashMap.newKeySet();
    private final OAuthJwtProbeFactory probeFactory = new OAuthJwtProbeFactory();
    private final Supplier<AuthStrategy> authStrategySupplier;
    private final SessionBaselineFactory sessionBaselineFactory;

    public McpActiveOAuthTokenValidationCheck(ScanCheckSettings settings,
                                              Supplier<AuthStrategy> authStrategySupplier) {
        this(settings, authStrategySupplier, null, SessionBaselineFactory.burpDefault());
    }

    public McpActiveOAuthTokenValidationCheck(ScanCheckSettings settings,
                                              Supplier<AuthStrategy> authStrategySupplier,
                                              McpEventLog eventLog) {
        this(settings, authStrategySupplier, eventLog, SessionBaselineFactory.burpDefault());
    }

    McpActiveOAuthTokenValidationCheck(ScanCheckSettings settings,
                                       Supplier<AuthStrategy> authStrategySupplier,
                                       McpEventLog eventLog,
                                       SessionBaselineFactory sessionBaselineFactory) {
        super(settings, eventLog);
        this.authStrategySupplier = authStrategySupplier;
        this.sessionBaselineFactory = sessionBaselineFactory;
    }

    @Override
    public CheckDescriptor descriptor() {
        return DESCRIPTOR;
    }

    @Override
    public void clearSessionState() {
        probedKeys.clear();
    }

    @Override
    protected AuditResult runCheck(HttpRequestResponse baseRequestResponse,
                                   AuditInsertionPoint insertionPoint, Http http) {
        if (!McpRequestDetector.classify(baseRequestResponse).isMcp()) {
            return AuditResult.auditResult(List.of());
        }
        HttpRequest baseline = baseRequestResponse.request();
        Optional<String> bearerToken = extractBearerToken(baseline);
        if (bearerToken.isEmpty() || !JwtShapeDetector.isJwtShape(bearerToken.get())) {
            return AuditResult.auditResult(List.of());
        }
        return AuditResult.auditResult(runProbePipeline(baseRequestResponse, http, bearerToken.get()));
    }

    @Override
    public List<AuditIssue> runOnceForSession(ScanStartContext context, Http http) {
        if (!isEnabledByDescriptor()) {
            return List.of();
        }
        return ScanCheckLogging.runIssuesAndLog(eventLog(), descriptor().id(),
                () -> probeSession(context, http));
    }

    private List<AuditIssue> probeSession(ScanStartContext context, Http http) {
        String bearer = contextBearer(context);
        if (bearer == null) {
            ScanCheckLogging.decisionSkipped(eventLog(), descriptor().id(),
                    "session has no Authorization bearer; JWT validation is moot");
            return List.of();
        }
        if (!JwtShapeDetector.isJwtShape(bearer)) {
            ScanCheckLogging.decisionSkipped(eventLog(), descriptor().id(),
                    "session bearer is not JWT-shaped");
            return List.of();
        }
        return runProbePipeline(sessionBaselineFactory.baselineFor(context), http, bearer);
    }

    private static String contextBearer(ScanStartContext context) {
        for (Map.Entry<String, String> entry : context.headers().entrySet()) {
            if (AUTHORIZATION_HEADER.equalsIgnoreCase(entry.getKey())) {
                String value = entry.getValue();
                if (value != null && value.regionMatches(true, 0, BEARER_PREFIX, 0, BEARER_PREFIX.length())) {
                    String token = value.substring(BEARER_PREFIX.length()).trim();
                    return token.isEmpty() ? null : token;
                }
            }
        }
        return null;
    }

    private List<AuditIssue> runProbePipeline(HttpRequestResponse baseRequestResponse, Http http,
                                              String bearerToken) {
        HttpRequest baseline = baseRequestResponse.request();
        String dedupKey = dedupKey(baseline);
        if (!probedKeys.add(dedupKey)) {
            return List.of();
        }

        JwtClaims claims = JwtShapeDetector.extractClaims(bearerToken)
                .orElse(new JwtClaims(List.of(), Optional.empty()));

        AuthStrategy authStrategy = authStrategySupplier.get();
        Set<String> headersToStrip = AuthProbes.authBearingHeaderNames(authStrategy);
        AuditIssueConfidence confidence = AuditIssueConfidence.FIRM;
        if (serverAcceptsStrippedAuth(http, baseline, headersToStrip)) {
            if (serverAcceptsGarbageBearer(http, baseline, headersToStrip)) {
                ScanCheckLogging.decisionSkipped(eventLog(), descriptor().id(),
                        "auth bypass dominates, JWT probes provide no differential signal");
                return List.of();
            }
            confidence = AuditIssueConfidence.TENTATIVE;
        }

        Map<String, HttpRequestResponse> successes = runProbes(http, baseline, headersToStrip, claims);
        if (successes.isEmpty()) {
            probedKeys.remove(dedupKey);
            return List.of();
        }
        return buildIssues(baseRequestResponse, successes, confidence);
    }

    private Map<String, HttpRequestResponse> runProbes(Http http, HttpRequest baseline,
                                                       Set<String> headersToStrip, JwtClaims claims) {
        List<JwtProbe> allProbes = probeFactory.mintProbes(claims.aud(), claims.iss());
        Map<String, HttpRequestResponse> successes = new LinkedHashMap<>();
        runSignedProbes(http, baseline, headersToStrip, allProbes, successes);
        runAlgNoneProbe(http, baseline, headersToStrip, allProbes, successes);
        return successes;
    }

    private static void runSignedProbes(Http http, HttpRequest baseline, Set<String> headersToStrip,
                                        List<JwtProbe> allProbes,
                                        Map<String, HttpRequestResponse> successes) {
        for (JwtProbe probe : allProbes) {
            if (OAuthJwtProbeFactory.LABEL_ALG_NONE.equals(probe.label())) {
                continue;
            }
            sendProbeAndRecord(http, baseline, headersToStrip, probe, successes);
            if (OAuthJwtProbeFactory.LABEL_RANDOM_SIG.equals(probe.label())
                    && successes.containsKey(OAuthJwtProbeFactory.LABEL_RANDOM_SIG)) {
                return;
            }
        }
    }

    private static void runAlgNoneProbe(Http http, HttpRequest baseline, Set<String> headersToStrip,
                                        List<JwtProbe> allProbes,
                                        Map<String, HttpRequestResponse> successes) {
        allProbes.stream()
                .filter(p -> OAuthJwtProbeFactory.LABEL_ALG_NONE.equals(p.label()))
                .findFirst()
                .ifPresent(probe -> sendProbeAndRecord(http, baseline, headersToStrip, probe, successes));
    }

    private static void sendProbeAndRecord(Http http, HttpRequest baseline, Set<String> headersToStrip,
                                           JwtProbe probe, Map<String, HttpRequestResponse> successes) {
        HttpRequestResponse response = http.sendRequest(applyProbe(baseline, probe, headersToStrip));
        if (McpRequestDetector.isToolCallSuccess(response)) {
            successes.put(probe.label(), response);
        }
    }

    private static boolean serverAcceptsStrippedAuth(Http http, HttpRequest baseline,
                                                     Set<String> headersToStrip) {
        HttpRequest stripped = HeaderMutation.apply(baseline, headersToStrip,
                ScannerSentinels.stripAuthOnly());
        return McpRequestDetector.isToolCallSuccess(http.sendRequest(stripped));
    }

    private static boolean serverAcceptsGarbageBearer(Http http, HttpRequest baseline,
                                                      Set<String> headersToStrip) {
        HttpRequest garbage = HeaderMutation.apply(baseline, headersToStrip,
                ScannerSentinels.withStripAuth(AUTHORIZATION_HEADER,
                        BEARER_PREFIX + GARBAGE_BEARER_PROBE_TOKEN));
        return McpRequestDetector.isToolCallSuccess(http.sendRequest(garbage));
    }

    private static HttpRequest applyProbe(HttpRequest baseline, JwtProbe probe,
                                          Set<String> headersToStrip) {
        return HeaderMutation.apply(baseline, headersToStrip,
                ScannerSentinels.withStripAuth(AUTHORIZATION_HEADER, BEARER_PREFIX + probe.token()));
    }

    private List<AuditIssue> buildIssues(HttpRequestResponse baseRequestResponse,
                                         Map<String, HttpRequestResponse> successes,
                                         AuditIssueConfidence confidence) {
        List<AuditIssue> issues = new ArrayList<>(2);
        buildBundledIssue(baseRequestResponse, successes, confidence).ifPresent(issues::add);
        buildAlgNoneIssue(baseRequestResponse, successes, confidence).ifPresent(issues::add);
        return issues;
    }

    private Optional<AuditIssue> buildBundledIssue(HttpRequestResponse baseRequestResponse,
                                                   Map<String, HttpRequestResponse> successes,
                                                   AuditIssueConfidence confidence) {
        IssueBodyBuilder body = new IssueBodyBuilder();
        Map<String, HttpRequestResponse> bundledSuccesses = new LinkedHashMap<>();

        if (successes.containsKey(OAuthJwtProbeFactory.LABEL_RANDOM_SIG)) {
            body.section(SECTION_SIGNATURE, paragraph(signatureWeaknessDetail()));
            bundledSuccesses.put(OAuthJwtProbeFactory.LABEL_RANDOM_SIG,
                    successes.get(OAuthJwtProbeFactory.LABEL_RANDOM_SIG));
        } else {
            collectClaimProbeSuccesses(successes, bundledSuccesses);
            if (bundledSuccesses.isEmpty()) {
                return Optional.empty();
            }
            appendClaimProbeBody(body, bundledSuccesses);
        }
        appendAuthBypassNoteIfTentative(body, confidence);

        String baseUrl = McpRequestDetector.extractBaseUrl(baseRequestResponse);
        return Optional.of(AuditIssue.auditIssue(
                ISSUE_NAME,
                body.build(),
                combinedRemediation(),
                baseUrl,
                AuditIssueSeverity.HIGH, confidence,
                IssueMetadataRenderer.background(
                        DESCRIPTOR.issueBackground(), DESCRIPTOR.cwes(), DESCRIPTOR.references()),
                null, AuditIssueSeverity.HIGH,
                List.copyOf(bundledSuccesses.values())
        ));
    }

    private static void collectClaimProbeSuccesses(Map<String, HttpRequestResponse> successes,
                                                   Map<String, HttpRequestResponse> bundledSuccesses) {
        collectIfPresent(successes, bundledSuccesses, OAuthJwtProbeFactory.LABEL_WRONG_AUD);
        collectIfPresent(successes, bundledSuccesses, OAuthJwtProbeFactory.LABEL_WRONG_ISS);
        collectIfPresent(successes, bundledSuccesses, OAuthJwtProbeFactory.LABEL_EXPIRED);
    }

    private static void collectIfPresent(Map<String, HttpRequestResponse> successes,
                                         Map<String, HttpRequestResponse> bundledSuccesses, String label) {
        if (successes.containsKey(label)) {
            bundledSuccesses.put(label, successes.get(label));
        }
    }

    private static void appendClaimProbeBody(IssueBodyBuilder body,
                                             Map<String, HttpRequestResponse> claimSuccesses) {
        if (claimSuccesses.size() > 1) {
            body.paragraph(BUNDLED_HEADLINE);
            body.findings(claimSuccessFindings(claimSuccesses));
        } else {
            String label = claimSuccesses.keySet().iterator().next();
            appendSingleClaimSection(body, label);
        }
    }

    private static List<String> claimSuccessFindings(Map<String, HttpRequestResponse> claimSuccesses) {
        List<String> items = new ArrayList<>();
        if (claimSuccesses.containsKey(OAuthJwtProbeFactory.LABEL_WRONG_AUD)) {
            items.add(SECTION_WRONG_AUD + ": " + wrongAudAcceptedDetail());
        }
        if (claimSuccesses.containsKey(OAuthJwtProbeFactory.LABEL_WRONG_ISS)) {
            items.add(SECTION_WRONG_ISS + ": " + wrongIssAcceptedDetail());
        }
        if (claimSuccesses.containsKey(OAuthJwtProbeFactory.LABEL_EXPIRED)) {
            items.add(SECTION_EXPIRED + ": " + expiredAcceptedDetail());
        }
        return items;
    }

    private static void appendSingleClaimSection(IssueBodyBuilder body, String label) {
        switch (label) {
            case OAuthJwtProbeFactory.LABEL_WRONG_AUD ->
                    body.section(SECTION_WRONG_AUD, paragraph(wrongAudAcceptedDetail()));
            case OAuthJwtProbeFactory.LABEL_WRONG_ISS ->
                    body.section(SECTION_WRONG_ISS, paragraph(wrongIssAcceptedDetail()));
            case OAuthJwtProbeFactory.LABEL_EXPIRED ->
                    body.section(SECTION_EXPIRED, paragraph(expiredAcceptedDetail()));
            default -> { }
        }
    }

    private Optional<AuditIssue> buildAlgNoneIssue(HttpRequestResponse baseRequestResponse,
                                                   Map<String, HttpRequestResponse> successes,
                                                   AuditIssueConfidence confidence) {
        HttpRequestResponse algNoneEvidence = successes.get(OAuthJwtProbeFactory.LABEL_ALG_NONE);
        if (algNoneEvidence == null) {
            return Optional.empty();
        }
        IssueBodyBuilder body = new IssueBodyBuilder()
                .paragraph("The server accepted a JWT whose header declares alg:none and whose "
                        + "signature segment is empty, so it treats unsigned tokens as valid. This "
                        + "lets an attacker forge arbitrary claims — identity, audience, and expiry "
                        + "— without holding any signing key, which is the most severe class of "
                        + "JWT validation failure (RFC 8725 §3.2).");
        appendAuthBypassNoteIfTentative(body, confidence);

        String baseUrl = McpRequestDetector.extractBaseUrl(baseRequestResponse);
        return Optional.of(AuditIssue.auditIssue(
                ALG_NONE_ISSUE_NAME,
                body.build(),
                algNoneRemediation(),
                baseUrl,
                AuditIssueSeverity.HIGH, confidence,
                IssueMetadataRenderer.background(
                        DESCRIPTOR.issueBackground(), DESCRIPTOR.cwes(), DESCRIPTOR.references()),
                null, AuditIssueSeverity.HIGH,
                List.of(algNoneEvidence)
        ));
    }

    private static void appendAuthBypassNoteIfTentative(IssueBodyBuilder body, AuditIssueConfidence confidence) {
        if (confidence == AuditIssueConfidence.TENTATIVE) {
            body.paragraph(AUTH_BYPASS_NOTE);
        }
    }

    private static String paragraph(String text) {
        return new IssueBodyBuilder().paragraph(text).build();
    }

    private static String signatureWeaknessDetail() {
        return "The server accepted a JWT signed with a key it does not trust, so it does not "
                + "verify JWT signatures against the authorization server's JWKS. An attacker can "
                + "therefore mint a token with arbitrary claims (subject, audience, issuer, expiry) "
                + "and authenticate as any principal.";
    }

    private static Optional<String> extractBearerToken(HttpRequest request) {
        String value = request.headerValue(AUTHORIZATION_HEADER);
        if (value == null || !value.regionMatches(true, 0, BEARER_PREFIX, 0, BEARER_PREFIX.length())) {
            return Optional.empty();
        }
        String token = value.substring(BEARER_PREFIX.length()).trim();
        return token.isEmpty() ? Optional.empty() : Optional.of(token);
    }

    private static String dedupKey(HttpRequest baseline) {
        HttpService service = baseline.httpService();
        String scheme = service.secure() ? "https" : "http";
        return scheme + "://" + service.host() + ":" + service.port() + "/" + pathPrefix(baseline);
    }

    private static String pathPrefix(HttpRequest baseline) {
        String path = baseline.pathWithoutQuery();
        if (path == null || path.isBlank()) {
            return "";
        }
        String trimmed = path.startsWith("/") ? path.substring(1) : path;
        int slash = trimmed.indexOf('/');
        return slash < 0 ? trimmed : trimmed.substring(0, slash);
    }

    private static String wrongAudAcceptedDetail() {
        return "The server accepted a JWT it should have rejected: it was signed with a key the "
                + "server does not trust and its audience (aud) claim points to an "
                + "attacker-controlled resource.";
    }

    private static String wrongIssAcceptedDetail() {
        return "The server accepted a JWT it should have rejected: it was signed with a key the "
                + "server does not trust and its issuer (iss) claim is set to an "
                + "attacker-controlled authority.";
    }

    private static String expiredAcceptedDetail() {
        return "The server accepted a JWT it should have rejected: it was signed with a key the "
                + "server does not trust and its expiry (exp) claim is in the past.";
    }

    private static String algNoneRemediation() {
        return new IssueBodyBuilder()
                .paragraph("Reject alg:none outright. Enforce an explicit allow-list of signing "
                        + "algorithms (RS256/ES256/EdDSA) before invoking the JWT library's verifier; "
                        + "do not rely on the JWT's alg header to choose the verifier. See "
                        + "RFC 8725 §3.2 and RFC 9068 §2.1.")
                .build();
    }

    private static String combinedRemediation() {
        return new IssueBodyBuilder()
                .paragraph("Configure the JWT validation library to:")
                .findings(List.of(
                        "Verify RS256/ES256 signatures against the trusted JWKS published by the "
                                + "authorization server and reject any token whose signature does not "
                                + "verify against a known public key.",
                        "Reject tokens with alg:none and enforce an allow-list of expected signing "
                                + "algorithms (e.g. RS256 only); ensure the verification key type "
                                + "matches the algorithm to prevent algorithm-confusion attacks "
                                + "(RFC 8725 §3.1).",
                        "After signature verification, validate the aud claim against this server's "
                                + "resource identifier, validate the iss claim against the configured "
                                + "trusted authorization server, and reject tokens whose exp claim is "
                                + "in the past."))
                .paragraph("Reject invalid or expired tokens with HTTP 401 and a WWW-Authenticate: "
                        + "Bearer challenge per MCP 2025-11-25 #token-handling and RFC 9728 §5.1.")
                .build();
    }
}
