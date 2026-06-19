package com.mcpscanner.checks;

import burp.api.montoya.http.Http;
import burp.api.montoya.http.HttpService;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.api.montoya.scanner.AuditResult;
import burp.api.montoya.scanner.ConsolidationAction;
import burp.api.montoya.scanner.audit.insertionpoint.AuditInsertionPoint;
import burp.api.montoya.scanner.audit.issues.AuditIssue;
import burp.api.montoya.scanner.audit.issues.AuditIssueConfidence;
import burp.api.montoya.scanner.audit.issues.AuditIssueSeverity;
import burp.api.montoya.scanner.scancheck.ScanCheckType;
import com.fasterxml.jackson.databind.JsonNode;
import com.mcpscanner.auth.AuthStrategy;
import com.mcpscanner.auth.NoAuthStrategy;
import com.mcpscanner.auth.oauth.OAuthUrlValidator;
import com.mcpscanner.auth.oauth.discovery.DiscoverySource;
import com.mcpscanner.auth.oauth.discovery.MetadataParsers;
import com.mcpscanner.auth.oauth.discovery.OAuthWellKnownPaths;
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

import java.net.URI;
import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.function.Supplier;

/**
 * Observes whether an MCP server's OAuth discovery metadata advertises hostile URLs.
 *
 * <p><b>SSRF-gate intentionally bypassed.</b> Unlike the connect-time discovery probes
 * (which run through {@link com.mcpscanner.auth.oauth.safety.SuspiciousDestinationGate}
 * to refuse following hostile metadata), this scan check exists precisely to <i>observe</i>
 * what the target is advertising. It uses {@link OAuthUrlValidator#classify(java.net.URI)}
 * synchronously (no DNS resolution, no gate prompt) and Burp's {@code Http} facade for
 * the actual probe traffic — so the user's "fetch this suspicious URL?" prompt is never
 * raised, and the scan does not block on discovering an unsafe target.
 */
public class McpActiveOAuthMetadataSsrfCheck extends ManagedActiveCheck implements SessionScopedCheck {

    private static final String ISSUE_NAME = "MCP OAuth Discovery Metadata Exposes Unsafe URLs";
    private static final String WWW_AUTHENTICATE_HEADER = "WWW-Authenticate";
    private static final int UNAUTHENTICATED_PROBE_EXPECTED_STATUS = 401;

    private static final CheckDescriptor DESCRIPTOR = new CheckDescriptor(
            "oauth-metadata-ssrf",
            "MCP OAuth Discovery Metadata Exposes Unsafe URLs",
            "The server's OAuth discovery metadata advertises URLs that resolve to loopback, "
                    + "link-local, RFC1918, cloud-metadata, or non-HTTPS endpoints. A client that "
                    + "follows this metadata can be coerced into server-side request forgery or a "
                    + "credential downgrade.",
            AuditIssueSeverity.MEDIUM,
            ScanCheckType.PER_REQUEST,
            true,
            List.of(
                    "https://modelcontextprotocol.io/specification/2025-11-25/basic/authorization",
                    "https://datatracker.ietf.org/doc/html/rfc9728#section-7.7",
                    "https://nvd.nist.gov/vuln/detail/CVE-2025-6514",
                    "https://portswigger.net/research/hidden-oauth-attack-vectors"
            ),
            Optional.of(ISSUE_NAME),
            "The server's OAuth discovery metadata advertises endpoints pointing at "
                    + "internal/loopback/cloud-metadata hosts, which a client or proxy may fetch — an "
                    + "SSRF primitive.",
            List.of(new Cwe(918, "Server-Side Request Forgery (SSRF)"))
    );

    private final OAuthUrlValidator urlValidator;
    private final Supplier<AuthStrategy> authStrategySupplier;
    private final HostDedup hostDedup = new HostDedup();

    public McpActiveOAuthMetadataSsrfCheck(ScanCheckSettings settings) {
        this(settings, NoAuthStrategy::new, new OAuthUrlValidator(), null);
    }

    public McpActiveOAuthMetadataSsrfCheck(ScanCheckSettings settings, OAuthUrlValidator urlValidator) {
        this(settings, NoAuthStrategy::new, urlValidator, null);
    }

    public McpActiveOAuthMetadataSsrfCheck(ScanCheckSettings settings, McpEventLog eventLog) {
        this(settings, NoAuthStrategy::new, new OAuthUrlValidator(), eventLog);
    }

    public McpActiveOAuthMetadataSsrfCheck(ScanCheckSettings settings,
                                           OAuthUrlValidator urlValidator,
                                           McpEventLog eventLog) {
        this(settings, NoAuthStrategy::new, urlValidator, eventLog);
    }

    public McpActiveOAuthMetadataSsrfCheck(ScanCheckSettings settings,
                                           Supplier<AuthStrategy> authStrategySupplier,
                                           OAuthUrlValidator urlValidator,
                                           McpEventLog eventLog) {
        super(settings, eventLog);
        this.urlValidator = urlValidator;
        this.authStrategySupplier = authStrategySupplier != null ? authStrategySupplier : NoAuthStrategy::new;
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
    public ConsolidationAction consolidateIssues(AuditIssue existingIssue, AuditIssue newIssue) {
        return consolidateByName(ISSUE_NAME, existingIssue, newIssue);
    }

    @Override
    protected AuditResult runCheck(HttpRequestResponse baseRequestResponse,
                                   AuditInsertionPoint insertionPoint, Http http) {
        if (!McpRequestDetector.classify(baseRequestResponse).isMcp()) {
            return emptyResult();
        }
        if (!hostDedup.tryClaim(baseRequestResponse.request())) {
            ScanCheckLogging.decisionSkipped(eventLog(), descriptor().id(), "already probed host");
            return emptyResult();
        }
        List<ProbeOutcome> outcomes = runProbes(baseRequestResponse, http);
        // Release the claim when no probe in the sequence reached the server cleanly.
        // A pure HTTP-layer failure across all three probes shouldn't poison dedup —
        // a retry might surface real findings.
        if (!atLeastOneProbeReachedServer(outcomes)) {
            hostDedup.releaseIfHttpLayerErrored(baseRequestResponse.request());
        }
        List<OAuthMetadataSsrfFinding> findings = collectFindings(outcomes);
        if (findings.isEmpty()) {
            return emptyResult();
        }
        return AuditResult.auditResult(List.of(buildIssue(baseRequestResponse, outcomes, findings)));
    }

    private static boolean atLeastOneProbeReachedServer(List<ProbeOutcome> outcomes) {
        return outcomes.stream().anyMatch(outcome -> outcome.response().response() != null);
    }

    private List<ProbeOutcome> runProbes(HttpRequestResponse baseRequestResponse, Http http) {
        List<ProbeOutcome> outcomes = new ArrayList<>(3);
        HttpService service = baseRequestResponse.request().httpService();
        outcomes.add(runUnauthenticatedProbe(baseRequestResponse.request(), http));
        outcomes.add(runWellKnownProbe(http, service, DiscoverySource.PRM_WELL_KNOWN,
                OAuthWellKnownPaths.PRM_WELL_KNOWN_PATH));
        outcomes.add(runWellKnownProbe(http, service, DiscoverySource.AS_WELL_KNOWN,
                OAuthWellKnownPaths.AS_WELL_KNOWN_PATH));
        return outcomes;
    }

    private ProbeOutcome runUnauthenticatedProbe(HttpRequest baseline, Http http) {
        Set<String> headersToStrip = AuthProbes.authBearingHeaderNames(authStrategySupplier.get());
        HttpRequest stripped = HeaderMutation.apply(baseline, headersToStrip, ScannerSentinels.stripAuthOnly());
        HttpRequestResponse response = http.sendRequest(stripped);
        return new ProbeOutcome(DiscoverySource.WWW_AUTHENTICATE_HEADER, response);
    }

    private ProbeOutcome runWellKnownProbe(Http http, HttpService service, DiscoverySource source, String path) {
        String url = OAuthWellKnownPaths.buildUrl(service, path);
        HttpRequest request = HttpRequest.httpRequestFromUrl(url).withMethod("GET");
        HttpRequestResponse response = http.sendRequest(request);
        return new ProbeOutcome(source, response);
    }

    private List<OAuthMetadataSsrfFinding> collectFindings(List<ProbeOutcome> outcomes) {
        List<OAuthMetadataSsrfFinding> findings = new ArrayList<>();
        for (ProbeOutcome outcome : outcomes) {
            findings.addAll(extractFindings(outcome));
        }
        return findings;
    }

    private List<OAuthMetadataSsrfFinding> extractFindings(ProbeOutcome outcome) {
        HttpResponse response = outcome.response().response();
        if (response == null) {
            return List.of();
        }
        return switch (outcome.source()) {
            case WWW_AUTHENTICATE_HEADER -> extractWwwAuthenticateFindings(response);
            case PRM_WELL_KNOWN -> extractPrmFindings(response);
            case AS_WELL_KNOWN -> extractAsFindings(response);
        };
    }

    private List<OAuthMetadataSsrfFinding> extractWwwAuthenticateFindings(HttpResponse response) {
        if (response.statusCode() != UNAUTHENTICATED_PROBE_EXPECTED_STATUS) {
            return List.of();
        }
        String headerValue = response.headerValue(WWW_AUTHENTICATE_HEADER);
        Optional<URI> resourceMetadataUrl = MetadataParsers.parseResourceMetadataFromWwwAuthenticate(headerValue);
        if (resourceMetadataUrl.isEmpty()) {
            return List.of();
        }
        return classifySingleUrl(DiscoverySource.WWW_AUTHENTICATE_HEADER.displayPath(),
                "resource_metadata", resourceMetadataUrl.get())
                .map(List::of)
                .orElse(List.of());
    }

    private List<OAuthMetadataSsrfFinding> extractPrmFindings(HttpResponse response) {
        if (response.statusCode() != 200) {
            return List.of();
        }
        Optional<JsonNode> document = MetadataParsers.parseJsonObject(response.bodyToString());
        if (document.isEmpty()) {
            return List.of();
        }
        return classifyUrls(DiscoverySource.PRM_WELL_KNOWN.displayPath(), collectPrmUrls(document.get()));
    }

    private List<OAuthMetadataSsrfFinding> extractAsFindings(HttpResponse response) {
        if (response.statusCode() != 200) {
            return List.of();
        }
        Optional<JsonNode> document = MetadataParsers.parseJsonObject(response.bodyToString());
        if (document.isEmpty()) {
            return List.of();
        }
        return classifyUrls(DiscoverySource.AS_WELL_KNOWN.displayPath(),
                collectScalarUrls(document.get(), OAuthMetadataFields.AS_SCALAR_URL_FIELDS));
    }

    private Map<String, URI> collectPrmUrls(JsonNode document) {
        Map<String, URI> urls = new LinkedHashMap<>();
        urls.putAll(collectScalarUrls(document, OAuthMetadataFields.PRM_SCALAR_URL_FIELDS));
        for (String arrayField : OAuthMetadataFields.PRM_ARRAY_URL_FIELDS) {
            List<URI> values = readUrlArray(document, arrayField);
            for (int i = 0; i < values.size(); i++) {
                urls.put(arrayField + "[" + i + "]", values.get(i));
            }
        }
        return urls;
    }

    private Map<String, URI> collectScalarUrls(JsonNode document, List<String> fieldNames) {
        Map<String, URI> urls = new LinkedHashMap<>();
        for (String field : fieldNames) {
            readUrlScalar(document, field).ifPresent(uri -> urls.put(field, uri));
        }
        return urls;
    }

    private static URI toUri(String value) {
        if (value == null || value.isBlank()) {
            return null;
        }
        try {
            return URI.create(value);
        } catch (IllegalArgumentException e) {
            return null;
        }
    }

    private static Optional<URI> readUrlScalar(JsonNode document, String field) {
        JsonNode value = document.get(field);
        if (value == null || !value.isTextual()) {
            return Optional.empty();
        }
        return Optional.ofNullable(toUri(value.asText()));
    }

    private static List<URI> readUrlArray(JsonNode document, String field) {
        JsonNode value = document.get(field);
        if (value == null || !value.isArray()) {
            return Collections.emptyList();
        }
        List<URI> uris = new ArrayList<>();
        for (JsonNode element : value) {
            if (!element.isTextual()) {
                continue;
            }
            URI uri = toUri(element.asText());
            if (uri != null) {
                uris.add(uri);
            }
        }
        return uris;
    }

    private Optional<OAuthMetadataSsrfFinding> classifySingleUrl(String sourceDocument, String fieldPath, URI url) {
        Optional<String> classification = urlValidator.classify(url);
        if (classification.isEmpty() || OAuthUrlValidator.CLASSIFICATION_UNRESOLVABLE.equals(classification.get())) {
            return Optional.empty();
        }
        return Optional.of(new OAuthMetadataSsrfFinding(sourceDocument, fieldPath, url, classification.get()));
    }

    private List<OAuthMetadataSsrfFinding> classifyUrls(String sourceDocument, Map<String, URI> urlsByField) {
        List<OAuthMetadataSsrfFinding> findings = new ArrayList<>();
        for (Map.Entry<String, URI> entry : urlsByField.entrySet()) {
            classifySingleUrl(sourceDocument, entry.getKey(), entry.getValue()).ifPresent(findings::add);
        }
        return findings;
    }

    private AuditIssue buildIssue(HttpRequestResponse baseRequestResponse,
                                  List<ProbeOutcome> outcomes,
                                  List<OAuthMetadataSsrfFinding> findings) {
        String baseUrl = McpRequestDetector.extractBaseUrl(baseRequestResponse);
        String host = baseRequestResponse.request().httpService().host();
        // An intentionally private deploy (loopback / RFC1918) advertising http:// or internal
        // metadata is a dev-mode choice, not an SSRF gateway for production clients — de-rate it.
        boolean locallyReachable = HostReachability.isLocallyReachable(host);
        AuditIssueSeverity severity = locallyReachable
                ? AuditIssueSeverity.INFORMATION
                : AuditIssueSeverity.MEDIUM;
        return AuditIssue.auditIssue(
                ISSUE_NAME,
                renderDetail(findings, locallyReachable),
                renderRemediation(),
                baseUrl,
                severity, AuditIssueConfidence.FIRM,
                IssueMetadataRenderer.background(
                        DESCRIPTOR.issueBackground(), DESCRIPTOR.cwes(), DESCRIPTOR.references()),
                null, severity,
                collectEvidence(baseRequestResponse, outcomes, findings)
        );
    }

    private List<HttpRequestResponse> collectEvidence(HttpRequestResponse baseRequestResponse,
                                                     List<ProbeOutcome> outcomes,
                                                     List<OAuthMetadataSsrfFinding> findings) {
        List<HttpRequestResponse> evidence = new ArrayList<>();
        evidence.add(baseRequestResponse);
        for (ProbeOutcome outcome : outcomes) {
            if (findingsContainSource(findings, outcome.source())) {
                evidence.add(outcome.response());
            }
        }
        return evidence;
    }

    private static boolean findingsContainSource(List<OAuthMetadataSsrfFinding> findings, DiscoverySource source) {
        String displayPath = source.displayPath();
        return findings.stream().anyMatch(f -> displayPath.equals(f.sourceDocument()));
    }

    private static String renderDetail(List<OAuthMetadataSsrfFinding> findings, boolean locallyReachable) {
        Map<String, List<OAuthMetadataSsrfFinding>> grouped = new LinkedHashMap<>();
        for (OAuthMetadataSsrfFinding finding : findings) {
            grouped.computeIfAbsent(finding.sourceDocument(), k -> new ArrayList<>()).add(finding);
        }
        IssueBodyBuilder builder = new IssueBodyBuilder()
                .paragraph("This MCP server's OAuth discovery metadata advertises URLs that resolve "
                        + "to internal, link-local, cloud-metadata, or non-HTTPS endpoints. A "
                        + "conformant MCP client that follows this metadata would issue "
                        + "authentication requests against attacker-reachable hosts, coercing the "
                        + "client into SSRF, credential downgrade, or full credential capture.");
        for (Map.Entry<String, List<OAuthMetadataSsrfFinding>> entry : grouped.entrySet()) {
            builder.section("From " + entry.getKey(), new IssueBodyBuilder()
                    .findings(renderFindingItems(entry.getValue()))
                    .build());
        }
        builder.paragraph("Exploitability depends on the consuming client: a hardened client "
                + "refuses these URLs, while a vulnerable one (as in CVE-2025-6514) escalates "
                + "this to remote code execution.");
        if (locallyReachable) {
            builder.paragraph("This server is loopback or RFC1918, so the metadata is most likely a "
                    + "dev-mode choice. Confirm it is not also reachable by production-facing clients "
                    + "that would follow this metadata.");
        }
        return builder
                .build();
    }

    private static List<String> renderFindingItems(List<OAuthMetadataSsrfFinding> findings) {
        List<String> items = new ArrayList<>(findings.size());
        for (OAuthMetadataSsrfFinding finding : findings) {
            items.add(finding.fieldPath() + " = " + finding.url()
                    + " (" + finding.classification() + ")");
        }
        return items;
    }

    private static String renderRemediation() {
        return new IssueBodyBuilder()
                .paragraph("Advertise only HTTPS URLs that resolve to public hosts matching the "
                        + "issuer and resource identifiers.")
                .paragraph("Reject any OAuth discovery configuration that emits loopback, RFC1918, "
                        + "link-local, cloud-metadata, or plain http:// endpoints.")
                .build();
    }

    private static AuditResult emptyResult() {
        return AuditResult.auditResult(List.of());
    }

    private record ProbeOutcome(DiscoverySource source, HttpRequestResponse response) {}
}
