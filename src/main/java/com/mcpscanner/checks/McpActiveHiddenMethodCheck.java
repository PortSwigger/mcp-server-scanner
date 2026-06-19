package com.mcpscanner.checks;

import burp.api.montoya.http.Http;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.scanner.AuditResult;
import burp.api.montoya.scanner.audit.insertionpoint.AuditInsertionPoint;
import burp.api.montoya.scanner.audit.issues.AuditIssue;
import burp.api.montoya.scanner.audit.issues.AuditIssueConfidence;
import burp.api.montoya.scanner.audit.issues.AuditIssueSeverity;
import burp.api.montoya.scanner.scancheck.ScanCheckType;
import com.mcpscanner.checks.issue.Cwe;
import com.mcpscanner.checks.issue.IssueBodyBuilder;
import com.mcpscanner.checks.issue.IssueMetadataRenderer;
import com.mcpscanner.checks.registry.CheckDescriptor;
import com.mcpscanner.checks.registry.ManagedActiveCheck;
import com.mcpscanner.checks.registry.ScanCheckLogging;
import com.mcpscanner.checks.registry.ScanCheckSettings;
import com.mcpscanner.checks.registry.SessionScopedCheck;
import com.mcpscanner.logging.McpEventLog;
import com.mcpscanner.mcp.McpRequestDetector;

import java.util.ArrayList;
import java.util.List;
import java.util.Set;

public class McpActiveHiddenMethodCheck extends ManagedActiveCheck implements SessionScopedCheck {

    private static final String ISSUE_NAME = "MCP Hidden Method Exposed";

    private static final Set<String> DIAGNOSTIC_METHODS = Set.of("echo", "test");

    /**
     * Standard JSON-RPC / Open-RPC introspection methods shipped by stock libraries (e.g. jsonrpc4j,
     * json-rpc-2.0, geth-style dispatchers, Open-RPC service discovery). Exposing these is technically
     * info disclosure, but operators see MEDIUM alerts on them as false positives on framework defaults.
     * Demote to INFORMATION/TENTATIVE so findings are still visible without causing alarm.
     */
    private static final Set<String> INTROSPECTION_METHODS = Set.of(
            "system.listMethods", "system.methodHelp", "system.methodSignature",
            "rpc.discover", "rpc.describe"
    );

    private static final CheckDescriptor DESCRIPTOR = new CheckDescriptor(
            "hidden-method",
            ISSUE_NAME,
            "The server's JSON-RPC dispatcher exposes or recognises methods beyond the documented "
                    + "MCP surface, such as admin, debug, or internal handlers, giving an attacker "
                    + "functionality that should not be reachable.",
            AuditIssueSeverity.MEDIUM,
            ScanCheckType.PER_REQUEST,
            true,
            List.of(
                    "https://www.jsonrpc.org/specification",
                    "https://modelcontextprotocol.io/specification/2025-11-25/basic",
                    "https://cwe.mitre.org/data/definitions/749.html"
            ),
            "An undocumented JSON-RPC method that is not in the advertised tools/resources/prompts "
                    + "surface responds to requests, exposing functionality outside the documented "
                    + "capability set.",
            List.of(new Cwe(749, "Exposed Dangerous Method or Function"))
    );

    private final HostDedup hostDedup = new HostDedup();

    public McpActiveHiddenMethodCheck(ScanCheckSettings settings) {
        this(settings, null);
    }

    public McpActiveHiddenMethodCheck(ScanCheckSettings settings, McpEventLog eventLog) {
        super(settings, eventLog);
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
        if (!McpRequestDetector.classify(baseRequestResponse).isMcp()) {
            return AuditResult.auditResult(List.of());
        }
        if (!McpRequestDetector.isMcpResponseSuccess(baseRequestResponse)) {
            ScanCheckLogging.decisionSkipped(eventLog(), descriptor().id(),
                    "baseline not an initialized MCP success");
            return AuditResult.auditResult(List.of());
        }
        String authFingerprint = HostDedup.authFingerprint(baseRequestResponse.request());
        if (!hostDedup.tryClaim(baseRequestResponse.request(), authFingerprint)) {
            ScanCheckLogging.decisionSkipped(eventLog(), descriptor().id(), "already probed host");
            return AuditResult.auditResult(List.of());
        }

        List<JsonRpcMethodProbeRunner.ProbeResult> results = new JsonRpcMethodProbeRunner(http)
                .runAll(baseRequestResponse.request(), HiddenMethodWordlist.PROBES);

        if (!probeSequenceExecutedCleanly(results)) {
            hostDedup.releaseIfHttpLayerErrored(baseRequestResponse.request(), authFingerprint);
        }

        List<JsonRpcMethodProbeRunner.ProbeResult> exposed =
                resultsByClassification(results, JsonRpcMethodProbeRunner.Classification.SUSPICIOUS);
        List<JsonRpcMethodProbeRunner.ProbeResult> recognised =
                resultsByClassification(results, JsonRpcMethodProbeRunner.Classification.INTERESTING);

        if (exposed.isEmpty() && recognised.isEmpty()) {
            return AuditResult.auditResult(List.of());
        }

        String baseUrl = McpRequestDetector.extractBaseUrl(baseRequestResponse);
        return AuditResult.auditResult(List.of(buildIssue(baseUrl, exposed, recognised,
                headlineConfidence(exposed))));
    }

    private static boolean probeSequenceExecutedCleanly(
            List<JsonRpcMethodProbeRunner.ProbeResult> results) {
        return results.stream().anyMatch(
                result -> result.classification() != JsonRpcMethodProbeRunner.Classification.HTTP_LAYER_ERROR);
    }

    private static List<JsonRpcMethodProbeRunner.ProbeResult> resultsByClassification(
            List<JsonRpcMethodProbeRunner.ProbeResult> results,
            JsonRpcMethodProbeRunner.Classification classification) {
        return results.stream()
                .filter(result -> result.classification() == classification)
                .toList();
    }

    private static AuditIssue buildIssue(String baseUrl,
                                         List<JsonRpcMethodProbeRunner.ProbeResult> exposed,
                                         List<JsonRpcMethodProbeRunner.ProbeResult> recognised,
                                         AuditIssueConfidence confidence) {
        AuditIssueSeverity severity = headlineSeverity(exposed);
        return AuditIssue.auditIssue(
                ISSUE_NAME,
                renderDetail(exposed, recognised),
                renderRemediation(),
                baseUrl,
                severity, confidence,
                IssueMetadataRenderer.background(
                        DESCRIPTOR.issueBackground(), DESCRIPTOR.cwes(), DESCRIPTOR.references()),
                null, severity,
                combinedEvidence(exposed, recognised)
        );
    }

    private static String renderRemediation() {
        return new IssueBodyBuilder()
                .paragraph("Restrict the JSON-RPC dispatcher to the documented MCP method set and "
                        + "reject any unrecognised method with a -32601 (method not found) error.")
                .paragraph("Internal admin, debug, and diagnostic endpoints should not share the "
                        + "MCP listener.")
                .build();
    }

    private static AuditIssueSeverity headlineSeverity(List<JsonRpcMethodProbeRunner.ProbeResult> exposed) {
        if (exposed.isEmpty()) {
            return AuditIssueSeverity.INFORMATION;
        }
        boolean lowSeverityOnly = exposed.stream()
                .allMatch(result -> isDemotedMethod(result.probe().methodName()));
        return lowSeverityOnly ? AuditIssueSeverity.INFORMATION : AuditIssueSeverity.MEDIUM;
    }

    private static AuditIssueConfidence headlineConfidence(
            List<JsonRpcMethodProbeRunner.ProbeResult> exposed) {
        if (exposed.isEmpty()) {
            // Recognised-only findings rest on a server-defined error code, not an executed
            // method, so they are reported tentatively.
            return AuditIssueConfidence.TENTATIVE;
        }
        boolean introspectionOnly = exposed.stream()
                .allMatch(result -> INTROSPECTION_METHODS.contains(result.probe().methodName())
                        || DIAGNOSTIC_METHODS.contains(result.probe().methodName()));
        return introspectionOnly ? AuditIssueConfidence.TENTATIVE : AuditIssueConfidence.FIRM;
    }

    private static boolean isDemotedMethod(String methodName) {
        return DIAGNOSTIC_METHODS.contains(methodName)
                || INTROSPECTION_METHODS.contains(methodName);
    }

    private static String renderDetail(List<JsonRpcMethodProbeRunner.ProbeResult> exposed,
                                       List<JsonRpcMethodProbeRunner.ProbeResult> recognised) {
        IssueBodyBuilder builder = new IssueBodyBuilder();
        if (!exposed.isEmpty()) {
            builder.paragraph("Exposed: the server ran the following non-standard methods, so they "
                            + "are reachable beyond the documented MCP surface:")
                    .findings(probeLines(exposed));
        }
        if (!recognised.isEmpty()) {
            builder.paragraph("Recognised: the server returned a server-defined error for the "
                            + "following non-standard methods, so a handler exists for them rather "
                            + "than the server treating them as unknown:")
                    .findings(probeLines(recognised));
        }
        return builder
                .build();
    }

    private static List<String> probeLines(List<JsonRpcMethodProbeRunner.ProbeResult> results) {
        List<String> lines = new ArrayList<>(results.size());
        for (JsonRpcMethodProbeRunner.ProbeResult result : results) {
            lines.add(result.probe().methodName() + " -> " + renderOutcome(result));
        }
        return lines;
    }

    private static List<HttpRequestResponse> combinedEvidence(
            List<JsonRpcMethodProbeRunner.ProbeResult> exposed,
            List<JsonRpcMethodProbeRunner.ProbeResult> recognised) {
        List<HttpRequestResponse> combined = new ArrayList<>(exposed.size() + recognised.size());
        combined.addAll(evidence(exposed));
        combined.addAll(evidence(recognised));
        return combined;
    }

    private static String renderOutcome(JsonRpcMethodProbeRunner.ProbeResult result) {
        if (result.errorCode().isPresent()) {
            return result.errorCode().get() + " " + tierLabel(result.errorSignal());
        }
        return "success";
    }

    private static String tierLabel(JsonRpcMethodProbeRunner.ErrorSignal signal) {
        return switch (signal) {
            case METHOD_NOT_FOUND -> "(method not found)";
            case INVALID_PARAMS -> "(handler exists: rejected invalid parameters)";
            case INTERNAL_ERROR -> "(handler exists: returned an internal error)";
            case SERVER_DEFINED -> "(server-defined error code)";
            case OTHER_STANDARD -> "(standard JSON-RPC error)";
            case NONE -> "";
        };
    }

    private static List<HttpRequestResponse> evidence(List<JsonRpcMethodProbeRunner.ProbeResult> results) {
        return results.stream().map(JsonRpcMethodProbeRunner.ProbeResult::response).toList();
    }
}
