package com.mcpscanner.checks;

import burp.api.montoya.http.Http;
import burp.api.montoya.http.HttpService;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.scanner.AuditResult;
import burp.api.montoya.scanner.ConsolidationAction;
import burp.api.montoya.scanner.audit.insertionpoint.AuditInsertionPoint;
import burp.api.montoya.scanner.audit.issues.AuditIssue;
import burp.api.montoya.scanner.audit.issues.AuditIssueConfidence;
import burp.api.montoya.scanner.audit.issues.AuditIssueSeverity;
import burp.api.montoya.scanner.scancheck.ScanCheckType;
import com.fasterxml.jackson.databind.JsonNode;
import com.mcpscanner.auth.AuthStrategy;
import com.mcpscanner.checks.issue.Cwe;
import com.mcpscanner.checks.issue.IssueBodyBuilder;
import com.mcpscanner.checks.issue.IssueMetadataRenderer;
import com.mcpscanner.checks.registry.CheckDescriptor;
import com.mcpscanner.checks.registry.ManagedActiveCheck;
import com.mcpscanner.checks.registry.ScanCheckLogging;
import com.mcpscanner.checks.registry.ScanCheckSettings;
import com.mcpscanner.checks.registry.SessionScopedCheck;
import com.mcpscanner.client.TransportType;
import com.mcpscanner.logging.McpEventLog;
import com.mcpscanner.mcp.HeaderMutation;
import com.mcpscanner.mcp.McpObjectMapper;
import com.mcpscanner.mcp.McpRequestDetector;
import com.mcpscanner.mcp.ScannerSentinels;

import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.function.Supplier;

/**
 * Detects unauthenticated {@code tools/list} exposure across both deployment shapes:
 * when authentication is configured on the baseline the check strips and invalidates it
 * (catching auth that is not enforced on discovery), and when no authentication is present
 * it probes unauthenticated (catching discovery that is open by default).
 */
public class McpActiveUnauthenticatedToolDiscoveryCheck extends ManagedActiveCheck
        implements SessionScopedCheck {

    private static final String ISSUE_NAME = "MCP Unauthenticated Tool Discovery";

    private static final CheckDescriptor DESCRIPTOR = new CheckDescriptor(
            "unauth-tool-discovery",
            ISSUE_NAME,
            "The server returns its tool list to callers without valid credentials, letting an "
                    + "attacker enumerate every tool name, description, and input schema. This fires "
                    + "either when authentication is configured but not enforced on discovery, or when "
                    + "discovery is open by default. Only discovery is confirmed unauthenticated; tool "
                    + "execution may still be gated.",
            AuditIssueSeverity.INFORMATION,
            ScanCheckType.PER_REQUEST,
            true,
            List.of(
                    "https://modelcontextprotocol.io/specification/2025-11-25/basic/authorization#token-handling",
                    "https://modelcontextprotocol.io/specification/2025-11-25/basic/authorization",
                    "https://modelcontextprotocol.io/specification/2025-11-25/basic/security_best_practices",
                    "https://nvd.nist.gov/vuln/detail/CVE-2025-49596",
                    "https://cwe.mitre.org/data/definitions/306.html"
            ),
            "Capability discovery (tools/resources/prompts) succeeds with no credentials, "
                    + "publishing the server's full capability surface to anonymous callers.",
            List.of(new Cwe(306, "Missing Authentication for Critical Function"))
    );

    private final Supplier<AuthStrategy> authStrategySupplier;
    private final Supplier<TransportType> transportSupplier;
    private final Supplier<Optional<HttpService>> probeServiceSupplier;
    private final HostDedup hostDedup = new HostDedup();

    public McpActiveUnauthenticatedToolDiscoveryCheck(ScanCheckSettings settings,
                                                      Supplier<AuthStrategy> authStrategySupplier) {
        this(settings, authStrategySupplier, null);
    }

    public McpActiveUnauthenticatedToolDiscoveryCheck(ScanCheckSettings settings,
                                                      Supplier<AuthStrategy> authStrategySupplier,
                                                      McpEventLog eventLog) {
        this(settings, authStrategySupplier, eventLog, () -> null);
    }

    public McpActiveUnauthenticatedToolDiscoveryCheck(ScanCheckSettings settings,
                                                      Supplier<AuthStrategy> authStrategySupplier,
                                                      McpEventLog eventLog,
                                                      Supplier<TransportType> transportSupplier) {
        this(settings, authStrategySupplier, eventLog, transportSupplier, Optional::empty);
    }

    public McpActiveUnauthenticatedToolDiscoveryCheck(ScanCheckSettings settings,
                                                      Supplier<AuthStrategy> authStrategySupplier,
                                                      McpEventLog eventLog,
                                                      Supplier<TransportType> transportSupplier,
                                                      Supplier<Optional<HttpService>> probeServiceSupplier) {
        super(settings, eventLog);
        this.authStrategySupplier = authStrategySupplier;
        this.transportSupplier = transportSupplier != null ? transportSupplier : () -> null;
        this.probeServiceSupplier = probeServiceSupplier != null ? probeServiceSupplier : Optional::empty;
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
        // PER_REQUEST dispatch fires this self-discovering check once per insertion point; the
        // probe battery only needs to run once per host. Dedup on host + auth fingerprint so a
        // rotated credential re-probes (the result genuinely depends on the supplied credentials)
        // but the ~29 insertion points of one scan do not.
        HttpRequest baseRequest = baseRequestResponse.request();
        String identity = HostDedup.authFingerprint(baseRequest);
        if (!hostDedup.tryClaim(baseRequest, identity)) {
            ScanCheckLogging.decisionSkipped(eventLog(), descriptor().id(), "already probed host");
            return emptyResult();
        }
        AuthStrategy authStrategy = authStrategySupplier.get();
        HttpRequest probeBaseline = ProbeBaseline.route(baseRequest, probeServiceSupplier);
        ReachabilityTrackingHttp trackedHttp = new ReachabilityTrackingHttp(http);
        AuditResult result = AuthProbes.hasAuthBearingHeaders(baseRequest, authStrategy)
                ? auditAuthNotEnforced(baseRequestResponse, probeBaseline, authStrategy, trackedHttp)
                : auditNoAuth(baseRequestResponse, probeBaseline, authStrategy, trackedHttp);
        if (result.auditIssues().isEmpty() && !trackedHttp.reachedServer()) {
            // Release the claim only when the probe never reached the server (it failed at the HTTP
            // layer) so a later insertion point retries; a clean negative from a reachable server
            // keeps the claim so the probe does not re-run per insertion point.
            hostDedup.releaseIfHttpLayerErrored(baseRequest, identity);
        }
        return result;
    }

    private AuditResult auditAuthNotEnforced(HttpRequestResponse baseRequestResponse,
                                             HttpRequest probeBaseline,
                                             AuthStrategy authStrategy, Http http) {
        HttpRequest toolsListBaseline =
                probeBaseline.withBody(ToolsListDiscovery.TOOLS_LIST_BODY);
        AuthProbeRunner runner = new AuthProbeRunner(http,
                McpActiveUnauthenticatedToolDiscoveryCheck::isToolsListLeak);
        List<AuthProbe> probes = new ArrayList<>();
        probes.add(AuthProbes.stripAuth(authStrategy));
        probes.addAll(AuthProbes.invalidTokenProbes(authStrategy));

        List<AuthProbeRunner.ProbeResult> successes = runner.runAll(toolsListBaseline, probes);
        if (successes.isEmpty()) {
            return emptyResult();
        }
        return AuditResult.auditResult(
                List.of(buildAuthNotEnforcedIssue(baseRequestResponse, successes)));
    }

    private AuditResult auditNoAuth(HttpRequestResponse baseRequestResponse,
                                    HttpRequest probeBaseline,
                                    AuthStrategy authStrategy, Http http) {
        HttpRequest probe = buildUnauthenticatedProbe(probeBaseline, authStrategy);
        HttpRequestResponse probeResponse = http.sendRequest(probe);
        if (!isToolsListLeak(probeResponse)) {
            return emptyResult();
        }
        return AuditResult.auditResult(
                List.of(buildNoAuthIssue(baseRequestResponse, probeResponse)));
    }

    private static HttpRequest buildUnauthenticatedProbe(HttpRequest baseline, AuthStrategy authStrategy) {
        // Strip only the credential-bearing headers and PRESERVE Mcp-Session-Id: the session is a
        // transport artifact, not authentication. Session-based servers (FastMCP Streamable HTTP,
        // SSE) reject a session-less request with a protocol error (-32600 / HTTP 400 "Missing
        // session ID") before any handler runs, so stripping the session would make the probe
        // malformed and silently hide genuinely-open discovery. Keeping the session yields a
        // well-formed "valid transport session, no credentials" request — the exact semantic the
        // finding claims. This branch only runs when the baseline carries no auth-bearing headers,
        // so there is no credential to leave behind. The strip sentinel tells SseProxyServer not to
        // re-inject the session's stored auth headers downstream of Burp.
        HttpRequest stripped = HeaderMutation.apply(
                baseline, AuthProbes.authBearingHeaderNames(authStrategy),
                ScannerSentinels.stripAuthOnly());
        return stripped.withBody(ToolsListDiscovery.TOOLS_LIST_BODY);
    }

    private static boolean isToolsListLeak(HttpRequestResponse response) {
        if (!McpRequestDetector.isNonErrorMcpResponse(response)) {
            return false;
        }
        String body = McpRequestDetector.jsonRpcBody(response.response());
        if (body == null || body.isEmpty()) {
            return false;
        }
        try {
            JsonNode tools = McpObjectMapper.INSTANCE.readTree(body).path("result").path("tools");
            return tools.isArray() && !tools.isEmpty();
        } catch (Exception ignored) {
            return false;
        }
    }

    private AuditIssue buildAuthNotEnforcedIssue(HttpRequestResponse baseRequestResponse,
                                                 List<AuthProbeRunner.ProbeResult> successes) {
        List<String> conditions = successes.stream()
                .map(result -> AuthProbes.describe(result.probe()))
                .toList();
        List<HttpRequestResponse> evidence = successes.stream()
                .map(AuthProbeRunner.ProbeResult::response)
                .toList();
        boolean sseTransport = transportSupplier.get() == TransportType.SSE;
        IssueBodyBuilder detailBuilder = new IssueBodyBuilder()
                .paragraph("Requests with no credentials or an invalid token still returned the "
                        + "tool list, so an attacker can enumerate the server's tools without valid "
                        + "credentials.")
                .section("Conditions that returned the tool list", new IssueBodyBuilder()
                        .findings(conditions)
                        .build())
                .paragraph("This confirms only that tool discovery is unauthenticated. Verify "
                        + "whether tool execution is gated separately before assuming the whole "
                        + "server is open.");
        if (sseTransport) {
            detailBuilder.paragraph(AuthProbes.SSE_SESSION_CAVEAT);
        }
        String detail = detailBuilder
                .build();
        String remediation = new IssueBodyBuilder()
                .paragraph("Require valid authentication for tools/list requests and reject "
                        + "requests that omit credentials or present invalid tokens.")
                .build();
        return buildIssue(baseRequestResponse, detail, remediation, evidence,
                sseTransport ? AuditIssueConfidence.TENTATIVE : AuditIssueConfidence.FIRM);
    }

    private AuditIssue buildNoAuthIssue(HttpRequestResponse baseRequestResponse,
                                        HttpRequestResponse probeResponse) {
        String host = baseRequestResponse.request().httpService().host();
        boolean locallyReachable = HostReachability.isLocallyReachable(host);
        return buildIssue(baseRequestResponse,
                renderNoAuthDetail(host, locallyReachable),
                renderNoAuthRemediation(),
                List.of(baseRequestResponse, probeResponse),
                AuditIssueConfidence.FIRM);
    }

    private static String renderNoAuthDetail(String host, boolean locallyReachable) {
        IssueBodyBuilder builder = new IssueBodyBuilder()
                .paragraph("With no credentials sent, the server still returned its tool list, so "
                        + "the discovery surface is exposed without any authentication. Only "
                        + "discovery is confirmed unauthenticated here; verify separately whether "
                        + "tool execution is also reachable without credentials.");
        if (locallyReachable) {
            builder.paragraph("Host " + host + " is loopback or RFC1918, so this may be an "
                    + "intentional local-dev configuration. Check whether the server is also "
                    + "reachable from other devices on the local network and whether the listed "
                    + "tool names reveal anything sensitive (filesystem paths, shell helpers, "
                    + "credential-handling tools).");
        } else {
            builder.paragraph("Host " + host + " appears publicly reachable, so any unauthenticated "
                    + "caller on the internet can enumerate the tool names, descriptions, and input "
                    + "schemas, which can leak deployment details and accelerate targeted attacks.");
        }
        return builder
                .build();
    }

    private static String renderNoAuthRemediation() {
        return new IssueBodyBuilder()
                .paragraph("If the server is reachable beyond loopback, place an authenticating "
                        + "reverse proxy in front of it and reject discovery requests that present "
                        + "no Authorization header with HTTP 401.")
                .paragraph("If the server is only meant for local use, bind the listener to "
                        + "127.0.0.1 so it is not reachable from the network.")
                .build();
    }

    private static AuditIssue buildIssue(HttpRequestResponse baseRequestResponse, String detail,
                                         String remediation, List<HttpRequestResponse> evidence,
                                         AuditIssueConfidence confidence) {
        return AuditIssue.auditIssue(
                ISSUE_NAME,
                detail,
                remediation,
                McpRequestDetector.extractBaseUrl(baseRequestResponse),
                AuditIssueSeverity.INFORMATION, confidence,
                IssueMetadataRenderer.background(
                        DESCRIPTOR.issueBackground(), DESCRIPTOR.cwes(), DESCRIPTOR.references()),
                null, AuditIssueSeverity.INFORMATION,
                evidence
        );
    }

    private static AuditResult emptyResult() {
        return AuditResult.auditResult(List.of());
    }
}
