package com.mcpscanner.checks;

import burp.api.montoya.http.Http;
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
import com.mcpscanner.checks.ToolsCallTraversalProbeRunner.ClassifiedFinding;
import com.mcpscanner.checks.ToolsCallTraversalProbeRunner.PrefixSiblingFinding;
import com.mcpscanner.checks.ToolsCallTraversalProbeRunner.TraversalHit;
import com.mcpscanner.checks.ToolsListDiscovery.DiscoveredTool;
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
import com.mcpscanner.mcp.McpToolDefinition;
import com.mcpscanner.scan.ScanInventory;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.function.Supplier;

public class McpActiveToolArgumentPathTraversalCheck extends ManagedActiveCheck
        implements SessionScopedCheck {

    private static final String TRAVERSAL_ISSUE_NAME = "MCP Tool Argument Path Traversal";
    private static final String ENCODING_BYPASS_ISSUE_NAME =
            "MCP Tool Argument Path Traversal (Encoding Bypass)";
    private static final String PREFIX_SIBLING_ISSUE_NAME =
            "MCP Tool Argument Path Traversal (Root Boundary Bypass)";
    private static final String FILE_READ_ISSUE_NAME = "MCP Tool Argument Arbitrary File Read";
    private static final int MAX_EVIDENCE_ENTRIES = 5;
    // Generous per-host/per-check cap on distinct (argument x payload) tools/call traversal probes.
    // The payload set is ~17 entries, so 600 covers dozens of path arguments while bounding fan-out
    // against a server that advertises a pathological number of path-like arguments.
    private static final int MAX_TRAVERSAL_PROBES = 600;

    private static final CheckDescriptor DESCRIPTOR = new CheckDescriptor(
            "tool-arg-traversal",
            TRAVERSAL_ISSUE_NAME,
            "A tool reads files from a path passed in its arguments without sandboxing, letting a "
                    + "client escape the intended base directory and read arbitrary files on the host.",
            AuditIssueSeverity.HIGH,
            ScanCheckType.PER_REQUEST,
            true,
            List.of(
                    "https://owasp.org/www-community/attacks/Path_Traversal",
                    "https://portswigger.net/web-security/file-path-traversal",
                    "https://nvd.nist.gov/vuln/detail/CVE-2025-53110"
            ),
            "A tool argument value flows into a filesystem path and can escape the intended root to "
                    + "read arbitrary files.",
            List.of(new Cwe(22, "Improper Limitation of a Pathname to a Restricted Directory "
                    + "('Path Traversal')"))
    );

    private static final String BACKGROUND = IssueMetadataRenderer.background(
            DESCRIPTOR.issueBackground(), DESCRIPTOR.cwes(), DESCRIPTOR.references());

    private static final String REMEDIATION = new IssueBodyBuilder()
            .paragraph("Sandbox every filesystem path that a tool accepts as input. Percent-decode "
                    + "the path fully before validation, canonicalise via realpath, reject absolute "
                    + "paths and file:// schemes, and confirm the resolved path is contained within an "
                    + "explicit allow-list root with a path-segment boundary check (not a string prefix "
                    + "match).")
            .paragraph("Note: symlink-based escapes (CVE-2025-53109), where a link inside the root "
                    + "resolves to a target outside it, cannot be exercised remotely over JSON-RPC and "
                    + "are out of scope for this check; defend against them by resolving symlinks before "
                    + "the containment check.")
            .build();

    private static final String TRAVERSAL_DETAIL_HEADER =
            "The tool returned the contents of files outside its base directory for the following "
                    + "argument values:";

    private static final String ENCODING_BYPASS_DETAIL_HEADER =
            "The tool rejected a literal ../ escape but returned the same out-of-base file when the "
                    + "traversal sequence was percent-encoded. This proves a path sanitizer is present "
                    + "but broken (it validates before decoding). The following encoded argument values "
                    + "disclosed files outside the base directory:";

    private static final String PREFIX_SIBLING_DETAIL_HEADER =
            "The tool validates its base directory with a naive string-prefix match (CVE-2025-53110): "
                    + "a non-existent sibling path that merely shares the root's string prefix passed the "
                    + "containment check (returning a filesystem not-found error) instead of being "
                    + "rejected as outside the allowed root. A correctly-bounded tool denies such a path "
                    + "before touching the filesystem. The following out-of-root probe demonstrated the "
                    + "boundary bypass:";

    private static final String FILE_READ_DETAIL_HEADER =
            "The tool read arbitrary absolute paths supplied in its arguments and returned their "
                    + "contents for the following values. If this tool is not meant to grant clients "
                    + "unrestricted filesystem access, treat this as a vulnerability. This may be "
                    + "working-as-designed for a deliberate file-exposure tool; verify against the "
                    + "intended sandbox root:";

    private final Supplier<ScanInventory> selectedInventorySupplier;
    private final HostDedup hostDedup = new HostDedup();

    public McpActiveToolArgumentPathTraversalCheck(ScanCheckSettings settings) {
        this(settings, null, ScanInventory::empty);
    }

    public McpActiveToolArgumentPathTraversalCheck(ScanCheckSettings settings, McpEventLog eventLog) {
        this(settings, eventLog, ScanInventory::empty);
    }

    public McpActiveToolArgumentPathTraversalCheck(ScanCheckSettings settings,
                                                   McpEventLog eventLog,
                                                   Supplier<ScanInventory> selectedInventorySupplier) {
        super(settings, eventLog);
        this.selectedInventorySupplier = selectedInventorySupplier != null
                ? selectedInventorySupplier
                : ScanInventory::empty;
    }

    @Override
    public void clearSessionState() {
        hostDedup.clear();
    }

    @Override
    public CheckDescriptor descriptor() {
        return DESCRIPTOR;
    }

    @Override
    public ConsolidationAction consolidateIssues(AuditIssue existingIssue, AuditIssue newIssue) {
        for (String name : List.of(TRAVERSAL_ISSUE_NAME, ENCODING_BYPASS_ISSUE_NAME,
                PREFIX_SIBLING_ISSUE_NAME, FILE_READ_ISSUE_NAME)) {
            if (consolidateByName(name, existingIssue, newIssue) == ConsolidationAction.KEEP_EXISTING) {
                return ConsolidationAction.KEEP_EXISTING;
            }
        }
        return ConsolidationAction.KEEP_BOTH;
    }

    @Override
    protected AuditResult runCheck(HttpRequestResponse baseRequestResponse,
                                   AuditInsertionPoint insertionPoint, Http http) {
        if (!McpRequestDetector.classify(baseRequestResponse).isMcp()) {
            return AuditResult.auditResult(List.of());
        }
        // PER_REQUEST dispatch fires this self-discovering check once per insertion point; the
        // tools/call probe battery only needs to run once per host. The result is
        // credential-independent (a traversal-prone tool resolves paths the same regardless of
        // bearer), so a plain host key is sufficient.
        if (!hostDedup.tryClaim(baseRequestResponse.request())) {
            ScanCheckLogging.decisionSkipped(eventLog(), descriptor().id(), "already probed host");
            return AuditResult.auditResult(List.of());
        }

        ReachabilityTrackingHttp trackedHttp = new ReachabilityTrackingHttp(http);
        List<AuditIssue> issues = probeForIssues(baseRequestResponse, trackedHttp);
        if (issues.isEmpty() && !trackedHttp.reachedServer()) {
            // Release the claim only when the battery never reached the server (every probe failed
            // at the HTTP layer) so a later insertion point retries; a clean negative from a
            // reachable server keeps the claim so the battery does not re-run per insertion point.
            hostDedup.releaseIfHttpLayerErrored(baseRequestResponse.request());
        }
        return AuditResult.auditResult(issues);
    }

    private List<AuditIssue> probeForIssues(HttpRequestResponse baseRequestResponse, Http http) {
        Set<String> selectedToolNames = SelectedToolsFilter.selectedToolNames(selectedInventorySupplier);
        if (selectedToolNames.isEmpty()) {
            logSkippedNoSelection();
            return List.of();
        }

        HttpRequest baseline = baseRequestResponse.request();
        ToolsCallTraversalProbeRunner runner = new ToolsCallTraversalProbeRunner(http);

        List<DiscoveredTool> discoveredTools = runner.discoverTools(baseline);
        List<DiscoveredTool> selectedTools = resolveSelectedTools(discoveredTools, selectedToolNames);
        if (selectedTools.isEmpty()) {
            return List.of();
        }
        List<ToolArgument> pathArguments = cappedArguments(runner.findPathArguments(selectedTools));
        if (pathArguments.isEmpty()) {
            return List.of();
        }

        List<ClassifiedFinding> findings =
                runner.probeAndClassify(baseline, pathArguments, ToolArgTraversalPayloads.all());
        // Root derivation may call a read-only list_allowed_directories-style tool that the user
        // did not select, so pass the FULL discovery list (the probe target stays the selected
        // path arguments).
        List<PrefixSiblingFinding> prefixSiblings =
                runner.probePrefixSibling(baseline, discoveredTools, pathArguments);

        return buildIssues(baseRequestResponse, findings, prefixSiblings);
    }

    /**
     * Resolves the user-selected tools to probe, preferring each tool's discovered {@code tools/list}
     * schema but falling back to the selected inventory's schema when discovery returns a schema with
     * no {@code properties} — some bridges (e.g. supergateway-fronted server-filesystem) strip the
     * inline property set from {@code tools/list}, which would otherwise hide every path argument.
     */
    private List<DiscoveredTool> resolveSelectedTools(List<DiscoveredTool> discoveredTools,
                                                      Set<String> selectedToolNames) {
        List<DiscoveredTool> resolved = new ArrayList<>();
        for (DiscoveredTool discovered : discoveredTools) {
            if (!selectedToolNames.contains(discovered.name())) {
                continue;
            }
            if (hasProperties(discovered.inputSchema())) {
                resolved.add(discovered);
            } else {
                resolved.add(withInventorySchema(discovered));
            }
        }
        return resolved;
    }

    private DiscoveredTool withInventorySchema(DiscoveredTool discovered) {
        for (McpToolDefinition tool : selectedInventorySupplier.get().tools()) {
            if (tool.name().equals(discovered.name()) && tool.hasProperties()) {
                JsonNode schema = parseSchema(tool.inputSchema());
                if (schema != null) {
                    return new DiscoveredTool(discovered.name(), schema);
                }
            }
        }
        return discovered;
    }

    private static boolean hasProperties(JsonNode schema) {
        return schema != null && schema.path("properties").isObject();
    }

    private static JsonNode parseSchema(String schemaJson) {
        try {
            return McpObjectMapper.INSTANCE.readTree(schemaJson);
        } catch (Exception ignored) {
            return null;
        }
    }

    private List<AuditIssue> buildIssues(HttpRequestResponse baseRequestResponse,
                                         List<ClassifiedFinding> findings,
                                         List<PrefixSiblingFinding> prefixSiblings) {
        String baseUrl = McpRequestDetector.extractBaseUrl(baseRequestResponse);
        List<AuditIssue> issues = new ArrayList<>();
        for (Map.Entry<TierToolArgKey, List<TraversalHit>> entry
                : groupByTierToolAndArgument(findings).entrySet()) {
            TierToolArgKey key = entry.getKey();
            issues.add(buildContentIssue(baseUrl, key.toolArgKey(), key.tier(), entry.getValue()));
        }
        for (Map.Entry<String, List<PrefixSiblingFinding>> entry
                : groupSiblingsByToolArg(prefixSiblings).entrySet()) {
            issues.add(buildPrefixSiblingIssue(baseUrl, entry.getKey(), entry.getValue()));
        }
        return issues;
    }

    private record TierToolArgKey(PathTraversalTier tier, String toolArgKey) {}

    private static Map<TierToolArgKey, List<TraversalHit>> groupByTierToolAndArgument(
            List<ClassifiedFinding> findings) {
        Map<TierToolArgKey, List<TraversalHit>> grouped = new LinkedHashMap<>();
        for (ClassifiedFinding finding : findings) {
            TierToolArgKey key = new TierToolArgKey(finding.tier(), toolArgKey(finding.argument()));
            grouped.computeIfAbsent(key, ignored -> new ArrayList<>()).addAll(finding.evidence());
        }
        return grouped;
    }

    private static Map<String, List<PrefixSiblingFinding>> groupSiblingsByToolArg(
            List<PrefixSiblingFinding> prefixSiblings) {
        Map<String, List<PrefixSiblingFinding>> grouped = new LinkedHashMap<>();
        for (PrefixSiblingFinding finding : prefixSiblings) {
            grouped.computeIfAbsent(toolArgKey(finding.argument()), ignored -> new ArrayList<>())
                    .add(finding);
        }
        return grouped;
    }

    private static String toolArgKey(ToolArgument argument) {
        return argument.tool().name() + "::" + argument.name();
    }

    private static AuditIssue buildContentIssue(String baseUrl, String toolArgKey,
                                                PathTraversalTier tier, List<TraversalHit> hits) {
        List<String> hitLines = new ArrayList<>(hits.size());
        for (TraversalHit hit : hits) {
            hitLines.add(hit.payload().value() + " -> matched "
                    + FileSignatureLabels.describe(hit.payload().expectedSignatures()) + " content");
        }
        return AuditIssue.auditIssue(
                issueName(tier),
                renderDetail(detailHeader(tier), toolArgKey, hitLines, hits.size()),
                REMEDIATION,
                baseUrl,
                severity(tier), confidence(tier),
                BACKGROUND, null, severity(tier),
                cappedResponses(hits.stream().map(TraversalHit::response).toList()));
    }

    private static AuditIssue buildPrefixSiblingIssue(String baseUrl, String toolArgKey,
                                                      List<PrefixSiblingFinding> findings) {
        List<String> hitLines = new ArrayList<>(findings.size());
        for (PrefixSiblingFinding finding : findings) {
            hitLines.add(finding.probedPath()
                    + " -> filesystem not-found for an out-of-root path (naive prefix-match bypass)");
        }
        return AuditIssue.auditIssue(
                PREFIX_SIBLING_ISSUE_NAME,
                renderDetail(PREFIX_SIBLING_DETAIL_HEADER, toolArgKey, hitLines, findings.size()),
                REMEDIATION,
                baseUrl,
                AuditIssueSeverity.MEDIUM, AuditIssueConfidence.FIRM,
                BACKGROUND, null, AuditIssueSeverity.MEDIUM,
                cappedResponses(findings.stream().map(PrefixSiblingFinding::response).toList()));
    }

    private static String renderDetail(String header, String toolArgKey,
                                       List<String> hitLines, int totalCount) {
        IssueBodyBuilder builder = new IssueBodyBuilder()
                .paragraph(header)
                .paragraph("Tool argument: " + toolArgKey)
                .findings(hitLines);
        if (totalCount > MAX_EVIDENCE_ENTRIES) {
            builder.paragraph("Showing first " + MAX_EVIDENCE_ENTRIES + " of " + totalCount
                    + " total request/response pairs in the evidence panel.");
        }
        return builder.build();
    }

    private static String issueName(PathTraversalTier tier) {
        return switch (tier) {
            case ENCODING_BYPASS -> ENCODING_BYPASS_ISSUE_NAME;
            case TRAVERSAL -> TRAVERSAL_ISSUE_NAME;
            case PREFIX_SIBLING -> PREFIX_SIBLING_ISSUE_NAME;
            case ABSOLUTE -> FILE_READ_ISSUE_NAME;
        };
    }

    private static AuditIssueSeverity severity(PathTraversalTier tier) {
        return switch (tier) {
            case ENCODING_BYPASS, TRAVERSAL -> AuditIssueSeverity.HIGH;
            case PREFIX_SIBLING, ABSOLUTE -> AuditIssueSeverity.MEDIUM;
        };
    }

    private static AuditIssueConfidence confidence(PathTraversalTier tier) {
        return switch (tier) {
            case ENCODING_BYPASS -> AuditIssueConfidence.CERTAIN;
            case TRAVERSAL, PREFIX_SIBLING -> AuditIssueConfidence.FIRM;
            case ABSOLUTE -> AuditIssueConfidence.TENTATIVE;
        };
    }

    private static String detailHeader(PathTraversalTier tier) {
        return switch (tier) {
            case ENCODING_BYPASS -> ENCODING_BYPASS_DETAIL_HEADER;
            case TRAVERSAL -> TRAVERSAL_DETAIL_HEADER;
            case PREFIX_SIBLING -> PREFIX_SIBLING_DETAIL_HEADER;
            case ABSOLUTE -> FILE_READ_DETAIL_HEADER;
        };
    }

    /** Caps the path arguments so total (argument x payload) probes stay under
     *  {@link #MAX_TRAVERSAL_PROBES}; logs an event line when coverage is truncated. */
    private List<ToolArgument> cappedArguments(List<ToolArgument> pathArguments) {
        int payloadCount = Math.max(1, ToolArgTraversalPayloads.all().size());
        int maxArguments = Math.max(1, MAX_TRAVERSAL_PROBES / payloadCount);
        if (pathArguments.size() <= maxArguments) {
            return pathArguments;
        }
        McpEventLog log = eventLog();
        if (log != null) {
            log.info("tool-arg-traversal: probe cap reached at " + MAX_TRAVERSAL_PROBES
                    + ", truncating coverage (" + pathArguments.size() + " path arguments x "
                    + payloadCount + " payloads queued)");
        }
        return pathArguments.subList(0, maxArguments);
    }

    private void logSkippedNoSelection() {
        McpEventLog log = eventLog();
        if (log != null) {
            log.info("tool-arg-traversal: no tools selected by user, skipping");
        }
    }

    private static List<HttpRequestResponse> cappedResponses(List<HttpRequestResponse> responses) {
        return responses.stream().limit(MAX_EVIDENCE_ENTRIES).toList();
    }
}
