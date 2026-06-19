package com.mcpscanner.checks;

import burp.api.montoya.http.Http;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.api.montoya.scanner.audit.issues.AuditIssue;
import burp.api.montoya.scanner.audit.issues.AuditIssueConfidence;
import burp.api.montoya.scanner.audit.issues.AuditIssueSeverity;
import burp.api.montoya.scanner.scancheck.ScanCheckType;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.mcpscanner.auth.AuthStrategy;
import com.mcpscanner.auth.NoAuthStrategy;
import com.mcpscanner.auth.oauth.discovery.BurpAuthorizationServerDiscovery;
import com.mcpscanner.auth.oauth.discovery.MetadataParsers;
import com.mcpscanner.checks.issue.Cwe;
import com.mcpscanner.checks.issue.IssueBodyBuilder;
import com.mcpscanner.checks.issue.IssueMetadataRenderer;
import com.mcpscanner.checks.registry.CheckDescriptor;
import com.mcpscanner.checks.registry.ManagedScanStartCheck;
import com.mcpscanner.checks.registry.ScanCheckLogging;
import com.mcpscanner.checks.registry.ScanCheckSettings;
import com.mcpscanner.checks.registry.SessionScopedCheck;
import com.mcpscanner.logging.McpEventLog;
import com.mcpscanner.mcp.McpObjectMapper;
import com.mcpscanner.mcp.McpRequestDetector;
import com.mcpscanner.scan.ScanStartContext;
import com.nimbusds.oauth2.sdk.as.AuthorizationServerMetadata;

import java.net.URI;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.HexFormat;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.function.Supplier;

/**
 * Detects a reflected-XSS precondition observed on a real MCP authorization server: an OAuth
 * authorization server that self-renders a consent page and echoes the attacker-controlled DCR
 * {@code client_name} into it un-encoded, in a tag-parsing (executable) context, with no mitigating
 * Content-Security-Policy.
 *
 * <p>Method (A–D): discover the AS metadata, register a client via DCR carrying an INERT structural
 * canary {@code client_name} (a {@code </script>} breakout + a benign custom-element marker — never
 * an executable payload), drive {@code /authorize} to reach the rendered consent HTML (following at
 * most one same-origin hop on a 302), then ask {@link ConsentReflectionAnalyzer} whether the canary
 * survived raw. Raw survival + non-mitigating CSP raises HIGH/FIRM; raw survival + mitigating CSP
 * downgrades to LOW; anything else raises nothing. The issue is honest that this is a precondition —
 * execution must be confirmed in a browser.
 */
public class McpActiveConsentPageReflectedXssCheck extends ManagedScanStartCheck
        implements SessionScopedCheck {

    private static final String ISSUE_NAME = "MCP OAuth Consent Page Reflected XSS";
    private static final String CONTENT_TYPE_HEADER = "Content-Type";
    private static final String ACCEPT_HEADER = "Accept";
    private static final String APPLICATION_JSON = "application/json";
    private static final String CSP_HEADER = "Content-Security-Policy";
    private static final String CANARY_PREFIX = "mcpxss-canary-";
    // The trust gate that decides whether an AS reflects the DCR client_name on its consent page is
    // not fixed across servers: some (one known server shape) reflect ONLY for loopback redirect_uris;
    // others may reflect ONLY for an https redirect. So we register ONE client carrying every
    // redirect style and drive /authorize once per style, analysing each consent page — rather than
    // assuming loopback ⇒ trusted. Both loopback forms are offered because some servers gate on only
    // one of 127.0.0.1 / localhost.
    private static final List<String> CANDIDATE_REDIRECT_URIS = List.of(
            "http://127.0.0.1:53682/callback",
            "http://localhost:53682/callback",
            "https://probe.example/cb");
    private static final int MAX_EVIDENCE_ENTRIES = 4;

    private static final CheckDescriptor DESCRIPTOR = new CheckDescriptor(
            "consent-page-reflected-xss",
            ISSUE_NAME,
            "The OAuth authorization server reflects the attacker-controlled DCR client_name into "
                    + "its consent page un-encoded, in an executable context with no mitigating "
                    + "Content-Security-Policy. An attacker who registers a client with a weaponised "
                    + "client_name can run script in the authorization origin when a victim views the "
                    + "consent screen.",
            AuditIssueSeverity.HIGH,
            ScanCheckType.PER_REQUEST,
            true,
            List.of(
                    "https://modelcontextprotocol.io/specification/2025-11-25/basic/authorization",
                    "https://datatracker.ietf.org/doc/html/rfc7591#section-2",
                    "https://owasp.org/www-community/attacks/xss/",
                    "https://portswigger.net/web-security/cross-site-scripting/reflected"
            ),
            Optional.of(ISSUE_NAME),
            "An OAuth registration/consent parameter (e.g. client_name) is reflected unescaped into "
                    + "the consent page, allowing script execution in the victim's browser — a path to "
                    + "account takeover.",
            List.of(new Cwe(79, "Improper Neutralization of Input During Web Page Generation "
                    + "('Cross-site Scripting')"))
    );

    private static final SecureRandom NONCE_RANDOM = new SecureRandom();

    private final BurpAuthorizationServerDiscovery discovery;
    private final HostDedup hostDedup = new HostDedup();
    private final SessionBaselineFactory sessionBaselineFactory;
    private final ConsentReflectionAnalyzer analyzer = new ConsentReflectionAnalyzer();
    private final ConsentUrlResolver consentUrlResolver = new ConsentUrlResolver();

    public McpActiveConsentPageReflectedXssCheck(ScanCheckSettings settings) {
        this(settings, new BurpAuthorizationServerDiscovery(), null, SessionBaselineFactory.burpDefault());
    }

    public McpActiveConsentPageReflectedXssCheck(ScanCheckSettings settings, McpEventLog eventLog) {
        this(settings, new BurpAuthorizationServerDiscovery(eventLog), eventLog, SessionBaselineFactory.burpDefault());
    }

    public McpActiveConsentPageReflectedXssCheck(ScanCheckSettings settings,
                                                 McpEventLog eventLog,
                                                 Supplier<AuthStrategy> authStrategySupplier) {
        this(settings,
                new BurpAuthorizationServerDiscovery(eventLog,
                        authStrategySupplier != null ? authStrategySupplier : NoAuthStrategy::new),
                eventLog,
                SessionBaselineFactory.burpDefault());
    }

    McpActiveConsentPageReflectedXssCheck(ScanCheckSettings settings,
                                          BurpAuthorizationServerDiscovery discovery,
                                          McpEventLog eventLog,
                                          SessionBaselineFactory sessionBaselineFactory) {
        super(settings, eventLog);
        this.discovery = discovery;
        this.sessionBaselineFactory = sessionBaselineFactory;
    }

    @Override
    public CheckDescriptor descriptor() {
        return DESCRIPTOR;
    }

    @Override
    public void clearSessionState() {
        hostDedup.clear();
    }

    @Override
    protected List<AuditIssue> probe(ScanStartContext context, Http http) {
        return probeForSession(sessionBaselineFactory.baselineFor(context), http);
    }

    private List<AuditIssue> probeForSession(HttpRequestResponse baseRequestResponse, Http http) {
        if (!hostDedup.tryClaim(baseRequestResponse.request())) {
            ScanCheckLogging.decisionSkipped(eventLog(), descriptor().id(), "already probed host");
            return List.of();
        }
        BurpAuthorizationServerDiscovery.Result discoveryResult = discovery.discover(http, baseRequestResponse);
        if (!atLeastOneProbeReachedServer(discoveryResult.probeResponses())) {
            hostDedup.releaseIfHttpLayerErrored(baseRequestResponse.request());
        }
        Optional<AuthorizationServerMetadata> metadata = discoveryResult.metadata();
        if (metadata.isEmpty()) {
            ScanCheckLogging.decisionSkipped(eventLog(), descriptor().id(),
                    "no authorization-server metadata discovered");
            return List.of();
        }
        URI registrationEndpoint = metadata.get().getRegistrationEndpointURI();
        if (registrationEndpoint == null) {
            ScanCheckLogging.decisionSkipped(eventLog(), descriptor().id(),
                    "AS metadata advertises no registration_endpoint");
            return List.of();
        }
        URI authorizationEndpoint = metadata.get().getAuthorizationEndpointURI();
        if (authorizationEndpoint == null) {
            ScanCheckLogging.decisionSkipped(eventLog(), descriptor().id(),
                    "AS metadata advertises no authorization_endpoint");
            return List.of();
        }

        Canary canary = newCanary();
        Optional<Registration> registration = register(http, registrationEndpoint, canary);
        if (registration.isEmpty()) {
            ScanCheckLogging.decisionSkipped(eventLog(), descriptor().id(),
                    "DCR rejected the canary client registration (no client_id issued)");
            return List.of();
        }

        return probeRedirectStyles(http, authorizationEndpoint, registration.get(), canary)
                .map(reflection -> List.of(buildIssue(
                        baseRequestResponse, registration.get(), reflection.consentPage(), reflection.verdict())))
                .orElseGet(List::of);
    }

    /**
     * Drives {@code /authorize} once per candidate redirect style against the single registered
     * client, analysing each reachable consent page, and returns the FIRST raw breakout found. A
     * server that reflects only for one redirect style (loopback OR https) is caught regardless of
     * which way the trust gate points; styles a server rejects simply yield no consent page.
     */
    private Optional<ConsentReflection> probeRedirectStyles(Http http, URI authorizationEndpoint,
                                                            Registration registration, Canary canary) {
        for (String redirectUri : CANDIDATE_REDIRECT_URIS) {
            Optional<ConsentPage> consentPage =
                    reachConsentPage(http, authorizationEndpoint, registration.clientId(), redirectUri);
            if (consentPage.isEmpty()) {
                continue;
            }
            ConsentReflectionAnalyzer.Verdict verdict =
                    analyzer.analyze(consentPage.get().body(), consentPage.get().csp(), canary.marker());
            if (verdict.isRawBreakout()) {
                return Optional.of(new ConsentReflection(consentPage.get(), verdict));
            }
            ScanCheckLogging.decisionSkipped(eventLog(), descriptor().id(),
                    "client_name not reflected raw for redirect " + redirectUri + " (" + verdict.context() + ")");
        }
        return Optional.empty();
    }

    private Optional<Registration> register(Http http, URI registrationEndpoint, Canary canary) {
        HttpRequestResponse response = http.sendRequest(
                buildRegistrationRequest(registrationEndpoint, canary.clientName(), CANDIDATE_REDIRECT_URIS));
        return clientIdFrom(response).map(clientId -> new Registration(clientId, response));
    }

    private Optional<ConsentPage> reachConsentPage(Http http, URI authorizationEndpoint,
                                                   String clientId, String redirectUri) {
        AuthorizeProbeRunner runner = new AuthorizeProbeRunner(http);
        AuthorizeProbeRunner.AuthorizeResult authorize = runner.send(new AuthorizeProbe(
                authorizationEndpoint, clientId, redirectUri, null));
        if (!authorize.reachedServer()) {
            return Optional.empty();
        }
        if (authorize.statusCode() == 200) {
            return Optional.of(consentPageFrom(authorize.exchange(), authorize.body()));
        }
        if (!isRedirect(authorize.statusCode())) {
            return Optional.empty();
        }
        Optional<ConsentPage> direct = fetchDirectSameOriginHop(runner, authorizationEndpoint, authorize);
        if (direct.isPresent()) {
            return direct;
        }
        return unwrapLoginBounce(runner, authorizationEndpoint, authorize);
    }

    private static Optional<ConsentPage> fetchDirectSameOriginHop(AuthorizeProbeRunner runner,
                                                                  URI authorizationEndpoint,
                                                                  AuthorizeProbeRunner.AuthorizeResult authorize) {
        AuthorizeProbeRunner.FetchResult hop =
                runner.fetchSameOrigin(authorizationEndpoint, authorize.location());
        return hop.fetched() ? Optional.of(consentPageFrom(hop.exchange(), hop.body())) : Optional.empty();
    }

    /**
     * When {@code /authorize} bounces to a sign-in page that carries the real consent URL in a query
     * parameter, recover the embedded AS-origin consent URL and fetch it exactly once. The candidate
     * is guaranteed (by {@link ConsentUrlResolver}) to share the AS origin, so the bounded follow-up
     * fetch can never leave the authorization origin (no SSRF/open-fetch primitive).
     */
    private Optional<ConsentPage> unwrapLoginBounce(AuthorizeProbeRunner runner,
                                                    URI authorizationEndpoint,
                                                    AuthorizeProbeRunner.AuthorizeResult authorize) {
        URI asOrigin = originOf(authorizationEndpoint);
        Optional<URI> consentUrl = consentUrlResolver.resolve(authorize.location(), asOrigin);
        if (consentUrl.isEmpty()) {
            return Optional.empty();
        }
        AuthorizeProbeRunner.FetchResult hop =
                runner.fetchSameOrigin(authorizationEndpoint, consentUrl.get().toString());
        return hop.fetched() ? Optional.of(consentPageFrom(hop.exchange(), hop.body())) : Optional.empty();
    }

    private static URI originOf(URI uri) {
        try {
            return new URI(uri.getScheme(), null, uri.getHost(), uri.getPort(), null, null, null);
        } catch (java.net.URISyntaxException e) {
            return uri;
        }
    }

    private static ConsentPage consentPageFrom(HttpRequestResponse exchange, String body) {
        HttpResponse response = exchange.response();
        String csp = response != null ? response.headerValue(CSP_HEADER) : null;
        return new ConsentPage(body, csp, exchange);
    }

    private static boolean isRedirect(int statusCode) {
        return statusCode == 301 || statusCode == 302 || statusCode == 303 || statusCode == 307 || statusCode == 308;
    }

    private static boolean atLeastOneProbeReachedServer(List<HttpRequestResponse> probeResponses) {
        return probeResponses.stream().anyMatch(rr -> rr.response() != null);
    }

    private static Optional<String> clientIdFrom(HttpRequestResponse response) {
        HttpResponse http = response.response();
        if (http == null) {
            return Optional.empty();
        }
        int status = http.statusCode();
        if (status != 200 && status != 201) {
            return Optional.empty();
        }
        return MetadataParsers.parseJsonObject(http.bodyToString())
                .map(node -> node.get("client_id"))
                .filter(node -> node != null && node.isTextual() && !node.asText().isBlank())
                .map(JsonNode::asText);
    }

    private static Canary newCanary() {
        byte[] bytes = new byte[8];
        NONCE_RANDOM.nextBytes(bytes);
        String nonce = HexFormat.of().formatHex(bytes);
        String markerTag = "<" + CANARY_PREFIX + nonce + ">";
        // Inert structural breakout only: a </script> island-exit plus a self-closing benign custom
        // element. No event handlers, no javascript:/data:, no script body — proves a tag-parsing
        // breakout survived encoding, never weaponises.
        String clientName = "mcpxss-" + nonce + "</script>" + markerTag + "</" + CANARY_PREFIX + nonce + ">";
        return new Canary(clientName, markerTag);
    }

    private static HttpRequest buildRegistrationRequest(URI registrationEndpoint, String clientName,
                                                        List<String> redirectUris) {
        return HttpRequest.httpRequestFromUrl(registrationEndpoint.toString())
                .withMethod("POST")
                .withBody(buildRegistrationBody(clientName, redirectUris))
                .withAddedHeader(CONTENT_TYPE_HEADER, APPLICATION_JSON)
                .withAddedHeader(ACCEPT_HEADER, APPLICATION_JSON);
    }

    private static String buildRegistrationBody(String clientName, List<String> redirectUris) {
        try {
            return McpObjectMapper.INSTANCE.writeValueAsString(Map.of(
                    "client_name", clientName,
                    "redirect_uris", redirectUris));
        } catch (JsonProcessingException e) {
            throw new IllegalStateException("Failed to build DCR registration body", e);
        }
    }

    private AuditIssue buildIssue(HttpRequestResponse baseRequestResponse,
                                  Registration registration,
                                  ConsentPage consentPage,
                                  ConsentReflectionAnalyzer.Verdict verdict) {
        AuditIssueSeverity severity = verdict.cspMitigates()
                ? AuditIssueSeverity.LOW
                : AuditIssueSeverity.HIGH;
        return AuditIssue.auditIssue(
                ISSUE_NAME,
                renderDetail(verdict),
                renderRemediation(),
                McpRequestDetector.extractBaseUrl(baseRequestResponse),
                severity, AuditIssueConfidence.FIRM,
                IssueMetadataRenderer.background(
                        DESCRIPTOR.issueBackground(), DESCRIPTOR.cwes(), DESCRIPTOR.references()),
                null, severity,
                collectEvidence(baseRequestResponse, registration, consentPage)
        );
    }

    private static String renderDetail(ConsentReflectionAnalyzer.Verdict verdict) {
        String contextDescription = switch (verdict.context()) {
            case RAW_SCRIPT_ISLAND ->
                    "reflected raw inside a <script> block — the highest-confidence executable context";
            case RAW_BODY_OR_ATTRIBUTE -> "in the HTML body or an attribute value";
            default -> "in an executable context";
        };
        IssueBodyBuilder builder = new IssueBodyBuilder()
                .paragraph("The OAuth authorization server reflected the attacker-controlled DCR "
                        + "client_name into its consent page un-encoded, " + contextDescription
                        + ". An attacker who registers a client with a weaponised client_name can run "
                        + "script in the authorization origin when a victim views the consent screen.")
                .paragraph("Reflection was confirmed at the HTTP layer, not execution — verify in a "
                        + "browser before treating it as exploitable.");
        if (verdict.cspMitigates()) {
            builder.paragraph("A Content-Security-Policy (CSP) without 'unsafe-inline' was present on "
                    + "the consent response, reducing exploitability — but fix the unescaped output "
                    + "anyway in case the policy changes or is bypassed.");
        } else {
            builder.paragraph("No mitigating Content-Security-Policy was present on the consent response "
                    + "(absent, or contains 'unsafe-inline' / a script wildcard), so a weaponised "
                    + "client_name would not be blocked by CSP.");
        }
        return builder.build();
    }

    private static String renderRemediation() {
        return new IssueBodyBuilder()
                .paragraph("HTML-encode (or strip) the client_name and every other DCR-supplied field "
                        + "before reflecting it into the consent page; client metadata is "
                        + "attacker-controlled. Prefer rendering such values client-side via textContent "
                        + "rather than server-side string interpolation.")
                .paragraph("Deploy a strict Content-Security-Policy on the authorization and consent "
                        + "origins: a script-src (or default-src fallback) without 'unsafe-inline' and "
                        + "without a script wildcard, as defence-in-depth against any residual reflection.")
                .build();
    }

    private static List<HttpRequestResponse> collectEvidence(HttpRequestResponse baseRequestResponse,
                                                             Registration registration,
                                                             ConsentPage consentPage) {
        List<HttpRequestResponse> evidence = new ArrayList<>();
        evidence.add(baseRequestResponse);
        evidence.add(registration.response());
        evidence.add(consentPage.exchange());
        if (evidence.size() > MAX_EVIDENCE_ENTRIES) {
            return evidence.subList(0, MAX_EVIDENCE_ENTRIES);
        }
        return evidence;
    }

    private record Canary(String clientName, String marker) {}

    private record Registration(String clientId, HttpRequestResponse response) {}

    private record ConsentPage(String body, String csp, HttpRequestResponse exchange) {}

    private record ConsentReflection(ConsentPage consentPage, ConsentReflectionAnalyzer.Verdict verdict) {}
}
