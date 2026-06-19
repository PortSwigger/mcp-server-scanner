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
import com.mcpscanner.mcp.McpRequestDetector;
import com.mcpscanner.mcp.McpObjectMapper;
import com.mcpscanner.scan.ScanStartContext;
import com.nimbusds.oauth2.sdk.as.AuthorizationServerMetadata;

import java.net.URI;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.HexFormat;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.function.Supplier;

public class McpActiveDcrMisconfigurationCheck extends ManagedScanStartCheck
        implements SessionScopedCheck {

    private static final String ISSUE_NAME = "MCP OAuth DCR Misconfiguration";
    private static final String CONTENT_TYPE_HEADER = "Content-Type";
    private static final String ACCEPT_HEADER = "Accept";
    private static final String APPLICATION_JSON = "application/json";
    private static final String PROBE_REDIRECT_URI = "https://probe.example/cb";
    private static final String PROBE_CLIENT_NAME = "scanner-probe";
    private static final String HTTP_DOWNGRADE_PROBE_ID = "HTTP_DOWNGRADE";
    private static final String WILDCARD_PROBE_ID = "WILDCARD_HOST";
    private static final int MAX_EVIDENCE_ENTRIES = 5;

    private static final CheckDescriptor DESCRIPTOR = new CheckDescriptor(
            "dcr-misconfiguration",
            "MCP OAuth DCR Misconfiguration",
            "The OAuth server accepts unauthenticated dynamic client registration and then honours "
                    + "an attacker-supplied redirect_uri at the authorization endpoint. An attacker "
                    + "can register their own client and steer a victim's authorization code to a "
                    + "host they control, leading to account takeover.",
            AuditIssueSeverity.MEDIUM,
            ScanCheckType.PER_REQUEST,
            true,
            List.of(
                    "https://modelcontextprotocol.io/specification/2025-11-25/basic/authorization#security-considerations",
                    "https://datatracker.ietf.org/doc/rfc9700/",
                    "https://datatracker.ietf.org/doc/html/rfc7591#section-3",
                    "https://portswigger.net/web-security/oauth"
            ),
            Optional.of(ISSUE_NAME),
            "Dynamic Client Registration accepts attacker-controlled values (such as arbitrary "
                    + "redirect URIs) without validation, weakening the OAuth trust model.",
            List.of(
                    new Cwe(1188, "Insecure Default Initialization of Resource"),
                    new Cwe(668, "Exposure of Resource to Wrong Sphere"))
    );

    private static final java.security.SecureRandom NONCE_RANDOM = new java.security.SecureRandom();

    private final BurpAuthorizationServerDiscovery discovery;
    private final HostDedup hostDedup = new HostDedup();
    private final SessionBaselineFactory sessionBaselineFactory;

    public McpActiveDcrMisconfigurationCheck(ScanCheckSettings settings) {
        this(settings, new BurpAuthorizationServerDiscovery(), null, SessionBaselineFactory.burpDefault());
    }

    public McpActiveDcrMisconfigurationCheck(ScanCheckSettings settings, McpEventLog eventLog) {
        this(settings, new BurpAuthorizationServerDiscovery(), eventLog, SessionBaselineFactory.burpDefault());
    }

    public McpActiveDcrMisconfigurationCheck(ScanCheckSettings settings,
                                             McpEventLog eventLog,
                                             Supplier<AuthStrategy> authStrategySupplier) {
        this(settings,
                new BurpAuthorizationServerDiscovery(eventLog,
                        authStrategySupplier != null ? authStrategySupplier : NoAuthStrategy::new),
                eventLog,
                SessionBaselineFactory.burpDefault());
    }

    McpActiveDcrMisconfigurationCheck(ScanCheckSettings settings, BurpAuthorizationServerDiscovery discovery) {
        this(settings, discovery, null, SessionBaselineFactory.burpDefault());
    }

    McpActiveDcrMisconfigurationCheck(ScanCheckSettings settings,
                                      BurpAuthorizationServerDiscovery discovery,
                                      McpEventLog eventLog) {
        this(settings, discovery, eventLog, SessionBaselineFactory.burpDefault());
    }

    McpActiveDcrMisconfigurationCheck(ScanCheckSettings settings,
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
        // Release the claim when no discovery probe reached the server:
        // pure HTTP-layer failures shouldn't poison dedup, a retry might succeed.
        if (!atLeastOneProbeReachedServer(discoveryResult.probeResponses())) {
            hostDedup.releaseIfHttpLayerErrored(baseRequestResponse.request());
        }
        Optional<AsDiscovery> asDiscovery = discoveryResult.metadata().map(McpActiveDcrMisconfigurationCheck::toAsDiscovery);
        if (asDiscovery.isEmpty()) {
            ScanCheckLogging.decisionSkipped(eventLog(), descriptor().id(),
                    "no authorization-server metadata discovered");
            return List.of();
        }
        URI registrationEndpoint = asDiscovery.get().registrationEndpoint();
        if (registrationEndpoint == null) {
            ScanCheckLogging.decisionSkipped(eventLog(), descriptor().id(),
                    "AS metadata advertises no registration_endpoint");
            return List.of();
        }

        PhaseAOutcome phaseA = runPhaseA(http, registrationEndpoint);
        if (phaseA.classification() != Classification.VULNERABLE) {
            return List.of();
        }

        List<PhaseBOutcome> phaseB = runPhaseB(http, registrationEndpoint, asDiscovery.get().issuerScheme());
        List<PhaseBOutcome> echoedHostile = phaseB.stream()
                .filter(o -> o.classification() == Classification.VULNERABLE)
                .toList();
        // Open registration alone is RFC 7591 §3-legal and fires on correctly-hardened public DCR
        // servers. Echoing a hostile redirect_uri at /register is also
        // legal storage — enforcement happens at /authorize. Only raise when Phase C confirms the
        // AS actually HONORS the hostile target.
        if (echoedHostile.isEmpty()) {
            ScanCheckLogging.decisionSkipped(eventLog(), descriptor().id(),
                    "open registration accepted but no hostile redirect_uri was echoed — "
                            + "RFC 7591 §3-legal, not raised as an issue");
            return List.of();
        }

        URI authorizationEndpoint = asDiscovery.get().authorizationEndpoint();
        if (authorizationEndpoint == null) {
            ScanCheckLogging.decisionSkipped(eventLog(), descriptor().id(),
                    "hostile redirect_uri echoed at /register but AS metadata advertises no "
                            + "authorization_endpoint — cannot confirm enforcement at /authorize, not raised");
            return List.of();
        }

        List<PhaseCOutcome> honored = runPhaseC(http, authorizationEndpoint, echoedHostile);
        Optional<AuditIssueSeverity> highestHonoredTier = honored.stream()
                .map(o -> o.phaseB().probe().tier())
                .max(SEVERITY_RANK);
        if (highestHonoredTier.isEmpty()) {
            ScanCheckLogging.decisionSkipped(eventLog(), descriptor().id(),
                    "hostile redirect_uri echoed at /register but /authorize rejected or did not "
                            + "honor it — enforcement is in place, not raised");
            return List.of();
        }
        return List.of(buildIssue(baseRequestResponse, phaseA, honored, highestHonoredTier.get()));
    }

    private List<PhaseCOutcome> runPhaseC(Http http, URI authorizationEndpoint,
                                          List<PhaseBOutcome> echoedHostile) {
        AuthorizeProbeRunner runner = new AuthorizeProbeRunner(http);
        List<PhaseCOutcome> honored = new ArrayList<>();
        for (PhaseBOutcome phaseB : echoedHostile) {
            // Authorize with the client from THIS registration (the one that echoed the hostile
            // redirect). A per-client redirect allow-list must be tested with that exact client,
            // not Phase A's benign-redirect client, or the AS would correctly reject and we'd miss it.
            String clientId = extractClientId(phaseB.response());
            String authorizeTarget = authorizeTargetFor(phaseB.probe());
            AuthorizeProbeRunner.AuthorizeResult result =
                    runner.send(new AuthorizeProbe(authorizationEndpoint, clientId, authorizeTarget, null));
            if (classifyAuthorize(result, phaseB.probe(), authorizeTarget) == Classification.VULNERABLE) {
                honored.add(new PhaseCOutcome(phaseB, authorizeTarget, result.exchange()));
            }
        }
        return honored;
    }

    private static String authorizeTargetFor(DcrRedirectUriProbe probe) {
        if (WILDCARD_PROBE_ID.equals(probe.id())) {
            // Testing the literal wildcard at /authorize would exact-match what was registered
            // and prove nothing. Use a DIFFERENT concrete subdomain to distinguish real
            // pattern-expansion from exact-match-only storage.
            return "https://evil-" + randomSubdomainNonce() + ".attacker.example/cb";
        }
        return probe.redirectUri();
    }

    private static String randomSubdomainNonce() {
        byte[] bytes = new byte[6];
        NONCE_RANDOM.nextBytes(bytes);
        return HexFormat.of().formatHex(bytes);
    }

    private static Classification classifyAuthorize(AuthorizeProbeRunner.AuthorizeResult result,
                                                    DcrRedirectUriProbe probe, String authorizeTarget) {
        if (!result.reachedServer()) {
            return Classification.INCONCLUSIVE;
        }
        int status = result.statusCode();
        if (status == 400 || status == 401 || status == 403) {
            return Classification.SECURE;
        }
        String location = result.location();
        if (locationHonorsTarget(location, probe, authorizeTarget)) {
            return Classification.VULNERABLE;
        }
        if (bodyOrLocationRejects(result.body(), location)) {
            return Classification.SECURE;
        }
        // Anything else (e.g. a 302 bounce to a login page that does not commit to the hostile
        // target) is ambiguous — pre-login bouncing is not proof of honoring. Suppress.
        return Classification.INCONCLUSIVE;
    }

    private static boolean locationHonorsTarget(String location, DcrRedirectUriProbe probe, String authorizeTarget) {
        if (location == null || location.isBlank()) {
            return false;
        }
        // For http/https probes (PATH_TRAVERSAL, WILDCARD_HOST, HTTP_DOWNGRADE), honoring must be
        // proven by an exact prefix match on the hostile target — a normal login-bounce to some
        // other https URL must NOT count. Known limitation: a server that NORMALISES the path
        // before redirecting (e.g. collapses /cb/../bypass to /bypass) is a false negative here;
        // we accept that to keep the false-positive rate at zero.
        if (location.startsWith(authorizeTarget)) {
            return true;
        }
        // Exotic (non-http/https) schemes — javascript:/data: — cannot meaningfully be matched by
        // prefix once the AS rewrites them, so any Location emitting that scheme proves acceptance.
        String scheme = schemeOf(probe.redirectUri());
        return isExoticScheme(scheme) && location.toLowerCase().startsWith(scheme + ":");
    }

    private static boolean isExoticScheme(String scheme) {
        return scheme != null
                && !scheme.equalsIgnoreCase("http")
                && !scheme.equalsIgnoreCase("https");
    }

    private static boolean bodyOrLocationRejects(String body, String location) {
        return containsRedirectRejection(body) || containsRedirectRejection(location);
    }

    private static boolean containsRedirectRejection(String text) {
        // Only the redirect-specific error counts as proof of rejection. Generic OAuth errors
        // (e.g. invalid_request) can be raised for PKCE/scope/client reasons unrelated to the
        // redirect_uri, and a vulnerable consent page can itself contain both "redirect_uri" and
        // "error" — so a loose substring heuristic would FALSELY suppress genuine findings.
        return text != null && text.toLowerCase().contains("invalid_redirect_uri");
    }

    private static String schemeOf(String uri) {
        int colon = uri.indexOf(':');
        return colon > 0 ? uri.substring(0, colon).toLowerCase() : null;
    }

    private static boolean atLeastOneProbeReachedServer(List<HttpRequestResponse> probeResponses) {
        return probeResponses.stream().anyMatch(rr -> rr.response() != null);
    }

    private static final Comparator<AuditIssueSeverity> SEVERITY_RANK =
            Comparator.comparingInt(McpActiveDcrMisconfigurationCheck::severityRank);

    private static int severityRank(AuditIssueSeverity severity) {
        return switch (severity) {
            case FALSE_POSITIVE -> -1;
            case INFORMATION -> 0;
            case LOW -> 1;
            case MEDIUM -> 2;
            case HIGH -> 3;
        };
    }

    private static AsDiscovery toAsDiscovery(AuthorizationServerMetadata metadata) {
        URI registrationEndpoint = metadata.getRegistrationEndpointURI();
        URI authorizationEndpoint = metadata.getAuthorizationEndpointURI();
        String issuerScheme = extractIssuerScheme(metadata);
        return new AsDiscovery(registrationEndpoint, authorizationEndpoint, issuerScheme);
    }

    private static String extractIssuerScheme(AuthorizationServerMetadata metadata) {
        if (metadata.getIssuer() == null) {
            return null;
        }
        try {
            URI issuerUri = URI.create(metadata.getIssuer().getValue());
            return issuerUri.getScheme();
        } catch (IllegalArgumentException e) {
            return null;
        }
    }

    private PhaseAOutcome runPhaseA(Http http, URI registrationEndpoint) {
        HttpRequest probe = buildRegistrationRequest(registrationEndpoint, PROBE_REDIRECT_URI);
        HttpRequestResponse response = http.sendRequest(probe);
        return new PhaseAOutcome(classifyRegistrationResponse(response), response);
    }

    private List<PhaseBOutcome> runPhaseB(Http http, URI registrationEndpoint, String issuerScheme) {
        List<PhaseBOutcome> outcomes = new ArrayList<>();
        for (DcrRedirectUriProbe probe : DcrRedirectUriProbe.PROBES) {
            if (shouldSkipProbe(probe, issuerScheme)) {
                continue;
            }
            HttpRequest request = buildRegistrationRequest(registrationEndpoint, probe.redirectUri());
            HttpRequestResponse response = http.sendRequest(request);
            outcomes.add(new PhaseBOutcome(probe, classifyPhaseBResponse(response, probe.redirectUri()), response));
        }
        return outcomes;
    }

    private static boolean shouldSkipProbe(DcrRedirectUriProbe probe, String issuerScheme) {
        return HTTP_DOWNGRADE_PROBE_ID.equals(probe.id()) && "http".equalsIgnoreCase(issuerScheme);
    }

    private static HttpRequest buildRegistrationRequest(URI registrationEndpoint, String redirectUri) {
        String body = buildRegistrationBody(redirectUri);
        return HttpRequest.httpRequestFromUrl(registrationEndpoint.toString())
                .withMethod("POST")
                .withBody(body)
                .withAddedHeader(CONTENT_TYPE_HEADER, APPLICATION_JSON)
                .withAddedHeader(ACCEPT_HEADER, APPLICATION_JSON);
    }

    private static String buildRegistrationBody(String redirectUri) {
        try {
            return McpObjectMapper.INSTANCE.writeValueAsString(Map.of(
                    "client_name", PROBE_CLIENT_NAME,
                    "redirect_uris", List.of(redirectUri)));
        } catch (JsonProcessingException e) {
            throw new IllegalStateException("Failed to build DCR registration body", e);
        }
    }

    private static Classification classifyRegistrationResponse(HttpRequestResponse response) {
        HttpResponse http = response.response();
        if (http == null) {
            return Classification.INCONCLUSIVE;
        }
        int status = http.statusCode();
        if (status == 200 || status == 201) {
            return hasClientId(http.bodyToString()) ? Classification.VULNERABLE : Classification.INCONCLUSIVE;
        }
        if (status == 401 || status == 403) {
            return Classification.SECURE;
        }
        return Classification.INCONCLUSIVE;
    }

    private static Classification classifyPhaseBResponse(HttpRequestResponse response, String submittedRedirectUri) {
        HttpResponse http = response.response();
        if (http == null) {
            return Classification.INCONCLUSIVE;
        }
        int status = http.statusCode();
        if (status == 401 || status == 403) {
            return Classification.SECURE;
        }
        if (status != 200 && status != 201) {
            return Classification.INCONCLUSIVE;
        }
        Optional<JsonNode> document = MetadataParsers.parseJsonObject(http.bodyToString());
        if (document.isEmpty() || !hasClientId(document.get())) {
            return Classification.INCONCLUSIVE;
        }
        return redirectUrisFrom(document.get())
                .map(uris -> uris.contains(submittedRedirectUri) ? Classification.VULNERABLE : Classification.INCONCLUSIVE)
                .orElse(Classification.INCONCLUSIVE);
    }

    private static boolean hasClientId(String body) {
        return MetadataParsers.parseJsonObject(body)
                .map(McpActiveDcrMisconfigurationCheck::hasClientId)
                .orElse(false);
    }

    private static boolean hasClientId(JsonNode document) {
        JsonNode clientId = document.get("client_id");
        return clientId != null && clientId.isTextual() && !clientId.asText().isBlank();
    }

    private static Optional<List<String>> redirectUrisFrom(JsonNode document) {
        JsonNode redirectUris = document.get("redirect_uris");
        if (redirectUris == null || !redirectUris.isArray()) {
            return Optional.empty();
        }
        return Optional.of(collectStrings(redirectUris));
    }

    private static List<String> collectStrings(JsonNode array) {
        List<String> values = new ArrayList<>();
        for (JsonNode element : array) {
            if (element != null && element.isTextual()) {
                values.add(element.asText());
            }
        }
        return values;
    }

    private AuditIssue buildIssue(HttpRequestResponse baseRequestResponse,
                                  PhaseAOutcome phaseA,
                                  List<PhaseCOutcome> honored,
                                  AuditIssueSeverity severity) {
        return AuditIssue.auditIssue(
                ISSUE_NAME,
                renderDetail(phaseA, honored),
                renderRemediation(),
                McpRequestDetector.extractBaseUrl(baseRequestResponse),
                severity, AuditIssueConfidence.FIRM,
                IssueMetadataRenderer.background(
                        DESCRIPTOR.issueBackground(), DESCRIPTOR.cwes(), DESCRIPTOR.references()),
                null, severity,
                collectEvidence(baseRequestResponse, phaseA, honored)
        );
    }

    private static String renderDetail(PhaseAOutcome phaseA, List<PhaseCOutcome> honored) {
        return new IssueBodyBuilder()
                .paragraph("The server accepted unauthenticated client registration (issued client_id '"
                        + extractClientId(phaseA.response()) + "') and stored these hostile redirect "
                        + "URIs without rejecting them:")
                .findings(renderRegisteredHostileRedirects(honored))
                .paragraph("The authorization endpoint then redirected to them:")
                .findings(renderHonoredRedirects(honored))
                .paragraph("An attacker can register their own client, send a victim a crafted "
                        + "authorization link, and have the authorization code delivered to an "
                        + "attacker-controlled URI, taking over the victim's account.")
                .build();
    }

    private static List<String> renderRegisteredHostileRedirects(List<PhaseCOutcome> honored) {
        List<String> items = new ArrayList<>(honored.size());
        for (PhaseCOutcome outcome : honored) {
            DcrRedirectUriProbe probe = outcome.phaseB().probe();
            items.add(probe.displayName() + " (" + probe.redirectUri() + ")");
        }
        return items;
    }

    private static List<String> renderHonoredRedirects(List<PhaseCOutcome> honored) {
        List<String> items = new ArrayList<>(honored.size());
        for (PhaseCOutcome outcome : honored) {
            items.add(outcome.phaseB().probe().displayName() + " redirected to " + outcome.authorizeTarget());
        }
        return items;
    }

    private static String extractClientId(HttpRequestResponse response) {
        HttpResponse http = response.response();
        if (http == null) {
            return "<unknown>";
        }
        return MetadataParsers.parseJsonObject(http.bodyToString())
                .map(node -> node.get("client_id"))
                .filter(node -> node != null && node.isTextual())
                .map(JsonNode::asText)
                .orElse("<unknown>");
    }

    private static String renderRemediation() {
        return new IssueBodyBuilder()
                .paragraph("Require an initial_access_token at the registration endpoint and "
                        + "strictly validate every redirect_uri: reject non-https schemes (in "
                        + "particular javascript:, data:, http://) and wildcard hosts, normalise "
                        + "paths before comparison, match against an exact pre-registered "
                        + "allow-list, and accept only localhost or HTTPS targets.")
                .paragraph("Alternatively, replace dynamic client registration with OAuth Client ID "
                        + "Metadata Documents, which avoid attacker-controlled client metadata "
                        + "entirely.")
                .build();
    }

    private static List<HttpRequestResponse> collectEvidence(HttpRequestResponse baseRequestResponse,
                                                             PhaseAOutcome phaseA,
                                                             List<PhaseCOutcome> honored) {
        List<HttpRequestResponse> evidence = new ArrayList<>();
        evidence.add(baseRequestResponse);
        evidence.add(phaseA.response());
        for (PhaseCOutcome outcome : honored) {
            if (evidence.size() >= MAX_EVIDENCE_ENTRIES) {
                break;
            }
            evidence.add(outcome.phaseB().response());
            if (evidence.size() < MAX_EVIDENCE_ENTRIES && outcome.authorizeExchange() != null) {
                evidence.add(outcome.authorizeExchange());
            }
        }
        return evidence;
    }

    private enum Classification { VULNERABLE, SECURE, INCONCLUSIVE }

    private record AsDiscovery(URI registrationEndpoint, URI authorizationEndpoint, String issuerScheme) {}

    private record PhaseAOutcome(Classification classification, HttpRequestResponse response) {}

    private record PhaseBOutcome(DcrRedirectUriProbe probe,
                                 Classification classification,
                                 HttpRequestResponse response) {}

    private record PhaseCOutcome(PhaseBOutcome phaseB,
                                 String authorizeTarget,
                                 HttpRequestResponse authorizeExchange) {}
}
