package com.mcpscanner.checks;

import burp.api.montoya.http.Http;
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
import com.mcpscanner.auth.NoAuthStrategy;
import com.mcpscanner.checks.DnsRebindingProbe.Category;
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

import java.util.ArrayList;
import java.util.EnumMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

public class McpActiveDnsRebindingCheck extends ManagedActiveCheck implements SessionScopedCheck {

    private static final String DNS_REBINDING_ISSUE_NAME = "MCP DNS Rebinding";
    private static final String ORIGIN_VALIDATION_ISSUE_NAME = "MCP Origin Header Validation";
    private static final String DISPLAY_NAME = "MCP DNS Rebinding / Origin Header Validation";
    private static final Set<Integer> SECURE_STATUS_CODES = Set.of(400, 401, 403, 421);

    private static final CheckDescriptor DESCRIPTOR = new CheckDescriptor(
            "dns-rebinding",
            DISPLAY_NAME,
            "MCP servers that accept browser-originated requests with hostile Origin or Host "
                    + "headers are exposed to DNS rebinding: a browser-resident attacker can reach a "
                    + "loopback or LAN-bound MCP endpoint from a hostile web origin and run tools as "
                    + "the victim.",
            AuditIssueSeverity.MEDIUM,
            ScanCheckType.PER_REQUEST,
            true,
            List.of(
                    "https://modelcontextprotocol.io/specification/2025-11-25/basic/transports#security-warning",
                    "https://github.com/modelcontextprotocol/typescript-sdk/security/advisories/GHSA-w48q-cv73-mx4w",
                    "https://github.com/modelcontextprotocol/python-sdk/security/advisories/GHSA-9h52-p55h-vw2f",
                    "https://nvd.nist.gov/vuln/detail/CVE-2025-49596"
            ),
            "MCP servers bound to loopback/LAN that don't validate Host/Origin can be reached from "
                    + "a hostile web page via DNS rebinding, letting a browser-resident attacker invoke "
                    + "tools as the victim.",
            List.of(new Cwe(350, "Reliance on Reverse DNS Resolution for a Security-Critical Action"))
    );

    private static final String ORIGIN_VALIDATION_BACKGROUND =
            "The server accepts arbitrary Origin headers, so it does not enforce the Origin "
                    + "allowlist the MCP transport mandates.";
    private static final List<Cwe> ORIGIN_VALIDATION_CWES =
            List.of(new Cwe(346, "Origin Validation Error"));

    private final HostDedup hostDedup = new HostDedup();

    public McpActiveDnsRebindingCheck(ScanCheckSettings settings) {
        this(settings, null);
    }

    public McpActiveDnsRebindingCheck(ScanCheckSettings settings, McpEventLog eventLog) {
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
    public ConsolidationAction consolidateIssues(AuditIssue existingIssue, AuditIssue newIssue) {
        if (consolidateByName(DNS_REBINDING_ISSUE_NAME, existingIssue, newIssue) == ConsolidationAction.KEEP_EXISTING) {
            return ConsolidationAction.KEEP_EXISTING;
        }
        if (consolidateByName(ORIGIN_VALIDATION_ISSUE_NAME, existingIssue, newIssue) == ConsolidationAction.KEEP_EXISTING) {
            return ConsolidationAction.KEEP_EXISTING;
        }
        return ConsolidationAction.KEEP_BOTH;
    }

    @Override
    protected AuditResult runCheck(HttpRequestResponse baseRequestResponse,
                                   AuditInsertionPoint insertionPoint, Http http) {
        if (!McpRequestDetector.classify(baseRequestResponse).isMcp()) {
            return emptyResult();
        }
        if (!hostDedup.tryClaim(baseRequestResponse.request())) {
            logDecisionSkipped("already probed host");
            return emptyResult();
        }
        if (!McpRequestDetector.isMcpResponseSuccess(baseRequestResponse)) {
            hostDedup.releaseIfHttpLayerErrored(baseRequestResponse.request());
            logDecisionSkipped("baseline did not produce a successful MCP response — no differential signal available");
            return emptyResult();
        }

        ProbeRun probeRun = runProbes(baseRequestResponse, http);
        Map<Category, List<ProbeOutcome>> outcomesByCategory = probeRun.outcomesByCategory();
        // Release the claim when no probe reached the server:
        // pure HTTP-layer failures shouldn't poison dedup, a retry might succeed.
        if (!probeRun.atLeastOneProbeReachedServer()) {
            hostDedup.releaseIfHttpLayerErrored(baseRequestResponse.request());
        }
        if (outcomesByCategory.isEmpty()) {
            return emptyResult();
        }

        List<AuditIssue> issues = new ArrayList<>(2);
        List<ProbeOutcome> hostOutcomes = outcomesByCategory.get(Category.HOST_OVERRIDE);
        if (hostOutcomes != null && !hostOutcomes.isEmpty()) {
            issues.add(buildDnsRebindingIssue(baseRequestResponse, hostOutcomes));
        }
        List<ProbeOutcome> originOutcomes = outcomesByCategory.get(Category.ORIGIN_OVERRIDE);
        if (originOutcomes != null && !originOutcomes.isEmpty()) {
            issues.add(buildOriginValidationIssue(baseRequestResponse, originOutcomes));
        }
        return AuditResult.auditResult(issues);
    }

    private ProbeRun runProbes(HttpRequestResponse baselineRequestResponse, Http http) {
        Map<Category, List<ProbeOutcome>> outcomes = new EnumMap<>(Category.class);
        boolean atLeastOneProbeReachedServer = false;
        HttpRequest baselineRequest = baselineRequestResponse.request();
        for (DnsRebindingProbe probe : DnsRebindingProbe.PROBES) {
            HttpRequest mutated = HeaderMutation.apply(
                    baselineRequest, probe.headersToRemove(), probe.headersToOverride());
            HttpRequestResponse probeResponse = http.sendRequest(mutated);
            if (probeResponse.response() != null) {
                atLeastOneProbeReachedServer = true;
            }
            Classification classification = classifyProbe(baselineRequestResponse, probeResponse);
            if (classification == Classification.VULNERABLE) {
                outcomes.computeIfAbsent(probe.category(), k -> new ArrayList<>())
                        .add(new ProbeOutcome(probe, probeResponse));
            } else if (classification == Classification.PROBE_DIVERGED) {
                logDecisionSkipped("probe " + probe.id()
                        + " returned a successful MCP response that diverged from baseline — "
                        + "server appears to filter by origin/host");
            }
        }
        return new ProbeRun(outcomes, atLeastOneProbeReachedServer);
    }

    private record ProbeRun(Map<Category, List<ProbeOutcome>> outcomesByCategory,
                            boolean atLeastOneProbeReachedServer) {}

    private static Classification classifyProbe(HttpRequestResponse baseline, HttpRequestResponse probe) {
        HttpResponse probeResponse = probe.response();
        if (probeResponse == null) {
            return Classification.INCONCLUSIVE;
        }
        int status = probeResponse.statusCode();
        if (SECURE_STATUS_CODES.contains(status)) {
            return Classification.SECURE;
        }
        if (status < 200 || status > 299) {
            return Classification.INCONCLUSIVE;
        }
        if (!McpRequestDetector.isMcpResponseSuccess(probe)) {
            return Classification.INCONCLUSIVE;
        }
        // Differential signal: probe is a successful MCP response AND its result envelope
        // (tool/resource/prompt names, initialize fingerprint, generic top-level keys)
        // structurally matches the baseline. A server that filters by Origin/Host returns
        // 200 OK with a different shape — that is correct behaviour, not the rebinding bug.
        return McpRequestDetector.responseShapesMatch(baseline, probe)
                ? Classification.VULNERABLE
                : Classification.PROBE_DIVERGED;
    }

    private void logDecisionSkipped(String reason) {
        ScanCheckLogging.decisionSkipped(eventLog(), descriptor().id(), reason);
    }

    private static AuditIssue buildDnsRebindingIssue(HttpRequestResponse baseRequestResponse,
                                                    List<ProbeOutcome> outcomes) {
        String baseUrl = McpRequestDetector.extractBaseUrl(baseRequestResponse);
        AuditIssueSeverity severity = dnsRebindingSeverity(baseRequestResponse);
        return AuditIssue.auditIssue(
                DNS_REBINDING_ISSUE_NAME,
                renderDnsRebindingDetail(baseRequestResponse, outcomes),
                renderRemediation(),
                baseUrl,
                severity, AuditIssueConfidence.FIRM,
                IssueMetadataRenderer.background(
                        DESCRIPTOR.issueBackground(), DESCRIPTOR.cwes(), DESCRIPTOR.references()),
                null, severity,
                List.of(baseRequestResponse, outcomes.get(0).response())
        );
    }

    private static AuditIssue buildOriginValidationIssue(HttpRequestResponse baseRequestResponse,
                                                        List<ProbeOutcome> outcomes) {
        String baseUrl = McpRequestDetector.extractBaseUrl(baseRequestResponse);
        // Origin-validation is LOW regardless of target: success here proves the server tolerates an unexpected Origin, not that an attacker can mount DNS rebinding.
        AuditIssueSeverity severity = AuditIssueSeverity.LOW;
        return AuditIssue.auditIssue(
                ORIGIN_VALIDATION_ISSUE_NAME,
                renderOriginValidationDetail(outcomes),
                renderRemediation(),
                baseUrl,
                severity, AuditIssueConfidence.FIRM,
                IssueMetadataRenderer.background(
                        ORIGIN_VALIDATION_BACKGROUND, ORIGIN_VALIDATION_CWES, DESCRIPTOR.references()),
                null, severity,
                List.of(baseRequestResponse, outcomes.get(0).response())
        );
    }

    private static AuditIssueSeverity dnsRebindingSeverity(HttpRequestResponse baseRequestResponse) {
        String host = baseRequestResponse.request().httpService().host();
        if (!HostReachability.isLocallyReachable(host)) {
            return AuditIssueSeverity.INFORMATION;
        }
        // The HOST_OVERRIDE probe replays the baseline's stored credentials, but a browser-based
        // DNS-rebinding attacker holds none. A credentialed loopback success therefore over-states
        // exploitability at MEDIUM — cap it at LOW until reachability without credentials is proven.
        return baselineCarriesCredentials(baseRequestResponse)
                ? AuditIssueSeverity.LOW
                : AuditIssueSeverity.MEDIUM;
    }

    private static boolean baselineCarriesCredentials(HttpRequestResponse baseRequestResponse) {
        return AuthProbes.hasAuthBearingHeaders(baseRequestResponse.request(), new NoAuthStrategy());
    }

    private static String renderDnsRebindingDetail(HttpRequestResponse baseRequestResponse,
                                                   List<ProbeOutcome> outcomes) {
        String host = baseRequestResponse.request().httpService().host();
        IssueBodyBuilder builder = new IssueBodyBuilder()
                .paragraph("The MCP server accepted a request whose Host header was rewritten to an "
                        + "attacker-controlled value alongside a matching attacker-controlled Origin "
                        + "— the exact shape a browser-driven DNS rebinding attack produces. The "
                        + "server validates neither Host nor Origin against an allowlist, so a "
                        + "browser-resident attacker can DNS-rebind to reach this loopback or "
                        + "LAN-bound endpoint from a hostile web origin and run tools as the victim.")
                .paragraph("The server accepted these spoofed headers:")
                .findings(probeVariantLabels(outcomes));
        if (!HostReachability.isLocallyReachable(host)) {
            builder.paragraph("The target host appears publicly reachable, where DNS rebinding does "
                    + "not apply (the attacker can already reach it directly). Host validation "
                    + "remains a defence-in-depth concern.");
        } else if (baselineCarriesCredentials(baseRequestResponse)) {
            builder.paragraph("The baseline request carried credentials (an Authorization header or "
                    + "cookies) that were reused on the spoofed request. A browser-based attacker "
                    + "would not hold those credentials, so confirm the endpoint is reachable "
                    + "unauthenticated before treating this as exploitable DNS rebinding.");
        }
        return builder.build();
    }

    private static String renderOriginValidationDetail(List<ProbeOutcome> outcomes) {
        return new IssueBodyBuilder()
                .paragraph("The MCP server accepted a request carrying an attacker-controlled Origin "
                        + "header, so it does not enforce the Origin allowlist the MCP transport spec "
                        + "mandates. The original request's credentials were reused on the spoofed "
                        + "request, so this confirms only that Origin enforcement is missing — the "
                        + "Host header was unchanged and a browser-resident attacker would not hold "
                        + "valid user credentials, so this is not by itself exploitable as DNS "
                        + "rebinding. Treat it as a CORS / spec-hardening gap.")
                .paragraph("The server accepted these spoofed Origins:")
                .findings(probeVariantLabels(outcomes))
                .build();
    }

    private static List<String> probeVariantLabels(List<ProbeOutcome> outcomes) {
        List<String> labels = new ArrayList<>(outcomes.size());
        for (ProbeOutcome outcome : outcomes) {
            labels.add(outcome.probe().displayName());
        }
        return labels;
    }

    private static String renderRemediation() {
        return new IssueBodyBuilder()
                .paragraph("Validate the Origin header on every MCP request and return 403 for any "
                        + "value outside an explicit allowlist. Use the SDK's built-in protection "
                        + "(FastMCP's TransportSecuritySettings, the TS SDK's "
                        + "hostHeaderValidation()), bind local MCP servers to 127.0.0.1 only, and "
                        + "require authentication on all tool execution endpoints.")
                .build();
    }

    private static AuditResult emptyResult() {
        return AuditResult.auditResult(List.of());
    }

    private enum Classification { VULNERABLE, SECURE, INCONCLUSIVE, PROBE_DIVERGED }

    private record ProbeOutcome(DnsRebindingProbe probe, HttpRequestResponse response) {}
}
