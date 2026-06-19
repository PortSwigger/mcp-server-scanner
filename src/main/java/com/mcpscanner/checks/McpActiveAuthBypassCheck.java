package com.mcpscanner.checks;

import burp.api.montoya.http.Http;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.scanner.AuditResult;
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
import com.mcpscanner.logging.McpEventLog;
import com.mcpscanner.mcp.McpObjectMapper;
import com.mcpscanner.mcp.McpRequestDetector;
import com.mcpscanner.mcp.McpRequestKind;

import java.util.ArrayList;
import java.util.List;
import java.util.function.Supplier;

public class McpActiveAuthBypassCheck extends ManagedActiveCheck implements SessionScopedCheck {

    private static final String DISPLAY_NAME = "MCP Authentication Bypass";

    private static final CheckDescriptor DESCRIPTOR = new CheckDescriptor(
            "auth-bypass",
            DISPLAY_NAME,
            "The server executes a tool call even when the request carries no credentials or an "
                    + "invalid token, so authentication is not enforced and an attacker can invoke "
                    + "the tool without valid credentials.",
            AuditIssueSeverity.MEDIUM,
            ScanCheckType.PER_REQUEST,
            true,
            List.of(
                    "https://modelcontextprotocol.io/specification/2025-11-25/basic/authorization#token-handling",
                    "https://modelcontextprotocol.io/specification/2025-11-25/basic/security_best_practices#token-passthrough",
                    "https://modelcontextprotocol.io/specification/2025-11-25/basic/security_best_practices#session-hijacking",
                    "https://datatracker.ietf.org/doc/html/rfc6750#section-2.1"
            ),
            "A protected MCP endpoint returned data without valid credentials, so authentication "
                    + "is not enforced on this surface.",
            List.of(new Cwe(287, "Improper Authentication"))
    );

    private final Supplier<AuthStrategy> authStrategySupplier;
    private final HostDedup hostDedup = new HostDedup();

    public McpActiveAuthBypassCheck(ScanCheckSettings settings, Supplier<AuthStrategy> authStrategySupplier) {
        this(settings, authStrategySupplier, null);
    }

    public McpActiveAuthBypassCheck(ScanCheckSettings settings,
                                    Supplier<AuthStrategy> authStrategySupplier,
                                    McpEventLog eventLog) {
        super(settings, eventLog);
        this.authStrategySupplier = authStrategySupplier;
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
    protected AuditResult runCheck(HttpRequestResponse baseRequestResponse,
                                   AuditInsertionPoint insertionPoint, Http http) {
        if (McpRequestDetector.classify(baseRequestResponse) != McpRequestKind.TOOLS_CALL) {
            return AuditResult.auditResult(List.of());
        }

        AuthStrategy authStrategy = authStrategySupplier.get();
        if (!AuthProbes.hasAuthBearingHeaders(baseRequestResponse.request(), authStrategy)) {
            return AuditResult.auditResult(List.of());
        }

        String authFingerprint = HostDedup.authFingerprint(baseRequestResponse.request());
        if (!hostDedup.tryClaim(baseRequestResponse.request(), authFingerprint)) {
            ScanCheckLogging.decisionSkipped(eventLog(), descriptor().id(),
                    "auth bypass already reported for this server");
            return AuditResult.auditResult(List.of());
        }

        AuthProbeRunner runner = new AuthProbeRunner(http, McpRequestDetector::isToolCallSuccess);
        AuthProbe stripAuth = AuthProbes.stripAuth(authStrategy);
        List<AuthProbe> probes = new ArrayList<>();
        probes.add(stripAuth);
        probes.addAll(AuthProbes.invalidTokenProbes(authStrategy));

        List<AuthProbeRunner.ProbeResult> successes = runner.runAll(baseRequestResponse.request(), probes);
        if (successes.isEmpty()) {
            // Release the claim so a future invocation can re-probe when no bypass
            // surfaced (e.g. probes failed at HTTP layer or returned 401).
            hostDedup.releaseIfHttpLayerErrored(baseRequestResponse.request(), authFingerprint);
            return AuditResult.auditResult(List.of());
        }

        String baseUrl = McpRequestDetector.extractBaseUrl(baseRequestResponse);
        String sampledTool = sampledToolName(baseRequestResponse.request());
        return AuditResult.auditResult(List.of(buildAuthNotEnforcedIssue(baseUrl, sampledTool, successes)));
    }

    private AuditIssue buildAuthNotEnforcedIssue(String baseUrl,
                                                 String sampledTool,
                                                 List<AuthProbeRunner.ProbeResult> successes) {
        List<String> acceptedConditions = successes.stream()
                .map(result -> AuthProbes.describe(result.probe()))
                .toList();
        List<HttpRequestResponse> evidence = successes.stream()
                .map(AuthProbeRunner.ProbeResult::response)
                .toList();
        // The proxy re-injects Mcp-Session-Id on BOTH transports, so the stripped probe always
        // reaches the server with a valid session. A positive proves the server trusts the session
        // id rather than fully anonymous access — TENTATIVE with the session-trust caveat regardless
        // of transport.
        return AuditIssue.auditIssue(
                DISPLAY_NAME,
                renderDetail(sampledTool, acceptedConditions),
                renderRemediation(),
                baseUrl,
                AuditIssueSeverity.MEDIUM,
                AuditIssueConfidence.TENTATIVE,
                IssueMetadataRenderer.background(
                        DESCRIPTOR.issueBackground(), DESCRIPTOR.cwes(), DESCRIPTOR.references()),
                null, AuditIssueSeverity.MEDIUM,
                evidence
        );
    }

    private static String sampledToolName(HttpRequest request) {
        try {
            JsonNode root = McpObjectMapper.INSTANCE.readTree(request.bodyToString());
            JsonNode name = root.path("params").path("name");
            return name.isTextual() ? name.asText() : "unknown";
        } catch (Exception e) {
            return "unknown";
        }
    }

    private static String renderDetail(String sampledTool, List<String> acceptedConditions) {
        return new IssueBodyBuilder()
                .paragraph("The server executed the tool \"" + sampledTool + "\" for requests that "
                        + "carried no valid credentials. This proves only that this one tool runs "
                        + "without valid authentication, not that every tool is equally reachable.")
                .paragraph("If \"" + sampledTool + "\" is intended to be public this is expected; "
                        + "otherwise the auth layer is not enforced for this tool.")
                .section("Conditions under which the tool ran", new IssueBodyBuilder()
                        .findings(acceptedConditions)
                        .build())
                .paragraph(AuthProbes.SESSION_TRUST_CAVEAT)
                .build();
    }

    private static String renderRemediation() {
        return new IssueBodyBuilder()
                .paragraph("Validate the Authorization header on every request and reject missing, "
                        + "invalid, or unbound tokens with HTTP 401.")
                .paragraph("Do not treat a session identifier (e.g. Mcp-Session-Id) as proof of "
                        + "authentication — verify the bearer token on every inbound request.")
                .build();
    }
}
