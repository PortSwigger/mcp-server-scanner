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
import com.mcpscanner.checks.ResourceTraversalPayloads.TraversalPayload;
import com.mcpscanner.checks.ResourcesReadProbeRunner.ClassifiedFinding;
import com.mcpscanner.checks.ResourcesReadProbeRunner.PrefixSiblingFinding;
import com.mcpscanner.checks.ResourcesReadProbeRunner.TraversalHit;
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
import com.mcpscanner.mcp.McpResourceDefinition;
import com.mcpscanner.scan.ScanInventory;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.function.Supplier;

public class McpActiveResourcePathTraversalCheck extends ManagedActiveCheck
        implements SessionScopedCheck {

    private static final String ENCODING_BYPASS_ISSUE_NAME = "MCP Resource Path Traversal (Encoding Bypass)";
    private static final String TRAVERSAL_ISSUE_NAME = "MCP Resource Path Traversal";
    private static final String PREFIX_SIBLING_ISSUE_NAME = "MCP Resource Path Traversal (Root Boundary Bypass)";
    private static final String FILE_READ_ISSUE_NAME = "MCP Resource Arbitrary File Read";
    private static final int MAX_EVIDENCE_ENTRIES = 5;
    // Generous per-host cap on distinct resources/read traversal probes. Each fixed/template/static
    // family is ~16 payloads; 600 keeps real coverage (dozens of templates and resources) while
    // bounding fan-out against a server that advertises a pathological number of resources.
    private static final int MAX_TRAVERSAL_PROBES = 600;

    private static final CheckDescriptor DESCRIPTOR = new CheckDescriptor(
            "resource-traversal",
            TRAVERSAL_ISSUE_NAME,
            "The resources/read handler resolves client-supplied URIs against the filesystem "
                    + "without sandboxing, letting a client read files outside the intended resource "
                    + "root and disclose arbitrary local files.",
            AuditIssueSeverity.HIGH,
            ScanCheckType.PER_REQUEST,
            true,
            List.of(
                    "https://modelcontextprotocol.io/specification/2025-11-25/server/resources#security-considerations",
                    "https://portswigger.net/web-security/file-path-traversal",
                    "https://nvd.nist.gov/vuln/detail/CVE-2025-53110"
            ),
            "A resources/read URI can escape the intended root to read arbitrary files on the "
                    + "server host.",
            List.of(new Cwe(22, "Improper Limitation of a Pathname to a Restricted Directory "
                    + "('Path Traversal')"))
    );

    private static final String REMEDIATION = new IssueBodyBuilder()
            .paragraph("Canonicalise every resources/read URI against an explicit sandbox root and "
                    + "reject any path that resolves outside it, regardless of encoding. Percent-decode "
                    + "fully before validation, resolve via realpath, and confirm containment with a "
                    + "path-segment boundary check (not a string prefix match). Disallow URI schemes "
                    + "the server does not need (for example file://).")
            .paragraph("Note: symlink-based escapes (CVE-2025-53109/67364), where a link inside the "
                    + "root resolves to a target outside it, cannot be exercised remotely over JSON-RPC "
                    + "and are out of scope for this check; defend against them by resolving symlinks "
                    + "before the containment check.")
            .build();

    private static final String BACKGROUND = IssueMetadataRenderer.background(
            DESCRIPTOR.issueBackground(), DESCRIPTOR.cwes(), DESCRIPTOR.references());

    private static final String ENCODING_BYPASS_DETAIL_HEADER =
            "The resources/read handler rejected a literal ../ escape but returned the same "
                    + "out-of-root file when the traversal sequence was percent-encoded. This proves a "
                    + "path sanitizer is present but broken (it validates before decoding). The "
                    + "following encoded URIs disclosed files outside the resource root:";

    private static final String TRAVERSAL_DETAIL_HEADER =
            "The resources/read handler returned the contents of files outside the resource root "
                    + "for the following URIs:";

    private static final String PREFIX_SIBLING_DETAIL_HEADER =
            "The resources/read handler validates the resource root with a naive string-prefix match "
                    + "(CVE-2025-53110): a non-existent sibling URI that merely shares the root's string "
                    + "prefix passed the containment check (returning a filesystem not-found error) "
                    + "instead of being rejected as outside the allowed root. A correctly-bounded handler "
                    + "denies such a URI before touching the filesystem. The following out-of-root probe "
                    + "demonstrated the boundary bypass:";

    private static final String FILE_READ_DETAIL_HEADER =
            "The resources/read handler served arbitrary absolute files with no path restriction "
                    + "for the following URIs. If this server is not intended to grant unrestricted "
                    + "filesystem access, treat this as a vulnerability. This may be working-as-designed "
                    + "for a deliberate file-exposure resource; verify against the intended sandbox root:";

    private final Supplier<ScanInventory> inventorySupplier;
    private final Supplier<Optional<HttpService>> probeServiceSupplier;
    private final HostDedup hostDedup = new HostDedup();

    public McpActiveResourcePathTraversalCheck(ScanCheckSettings settings) {
        this(settings, null, ScanInventory::empty);
    }

    public McpActiveResourcePathTraversalCheck(ScanCheckSettings settings, McpEventLog eventLog) {
        this(settings, eventLog, ScanInventory::empty);
    }

    public McpActiveResourcePathTraversalCheck(ScanCheckSettings settings,
                                               McpEventLog eventLog,
                                               Supplier<ScanInventory> inventorySupplier) {
        this(settings, eventLog, inventorySupplier, Optional::empty);
    }

    public McpActiveResourcePathTraversalCheck(ScanCheckSettings settings,
                                               McpEventLog eventLog,
                                               Supplier<ScanInventory> inventorySupplier,
                                               Supplier<Optional<HttpService>> probeServiceSupplier) {
        super(settings, eventLog);
        this.inventorySupplier = inventorySupplier != null ? inventorySupplier : ScanInventory::empty;
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
        for (String name : List.of(ENCODING_BYPASS_ISSUE_NAME, TRAVERSAL_ISSUE_NAME,
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
        // resources/read probe battery only needs to run once per host. The result is
        // credential-independent (a traversal handler resolves URIs the same regardless of bearer),
        // so a plain host key is sufficient.
        if (!hostDedup.tryClaim(baseRequestResponse.request())) {
            ScanCheckLogging.decisionSkipped(eventLog(), descriptor().id(), "already probed host");
            return AuditResult.auditResult(List.of());
        }

        HttpRequest baseline = ProbeBaseline.route(baseRequestResponse.request(), probeServiceSupplier);
        ReachabilityTrackingHttp trackedHttp = new ReachabilityTrackingHttp(http);
        ResourcesReadProbeRunner runner = new ResourcesReadProbeRunner(trackedHttp);

        List<String> resourceUris = discoveredResourceUris(runner, baseline);
        List<TraversalPayload> payloads = buildPayloads(runner, baseline, resourceUris);
        List<ClassifiedFinding> findings = runner.probeAndClassify(baseline, payloads);
        List<PrefixSiblingFinding> prefixSiblings = runner.probePrefixSibling(baseline, resourceUris);
        if (findings.isEmpty() && prefixSiblings.isEmpty()) {
            // Release the claim only when the battery never reached the server (every probe failed
            // at the HTTP layer) so a later insertion point retries; a clean negative from a
            // reachable server keeps the claim so the battery does not re-run per insertion point.
            if (!trackedHttp.reachedServer()) {
                hostDedup.releaseIfHttpLayerErrored(baseRequestResponse.request());
            }
            return AuditResult.auditResult(List.of());
        }

        return AuditResult.auditResult(buildIssues(baseRequestResponse, findings, prefixSiblings));
    }

    private List<TraversalPayload> buildPayloads(ResourcesReadProbeRunner runner, HttpRequest baseline,
                                                 List<String> resourceUris) {
        List<TraversalPayload> payloads = new ArrayList<>(ResourceTraversalPayloads.fixed());
        payloads.addAll(ResourceTraversalPayloads.fromTemplates(runner.discoverTemplateUris(baseline)));
        payloads.addAll(ResourceTraversalPayloads.fromStaticUris(resourceUris));
        return capPayloads(dedupePayloads(payloads));
    }

    /** Collapses payloads whose URI is identical (the same template variable can be discovered
     *  via both resources/list and the inventory) so a probe is sent once, not once per source. */
    private static List<TraversalPayload> dedupePayloads(List<TraversalPayload> payloads) {
        Map<String, TraversalPayload> byUri = new LinkedHashMap<>();
        for (TraversalPayload payload : payloads) {
            byUri.putIfAbsent(payload.uri(), payload);
        }
        return new ArrayList<>(byUri.values());
    }

    private List<TraversalPayload> capPayloads(List<TraversalPayload> payloads) {
        if (payloads.size() <= MAX_TRAVERSAL_PROBES) {
            return payloads;
        }
        logProbeCapReached(payloads.size());
        return payloads.subList(0, MAX_TRAVERSAL_PROBES);
    }

    private void logProbeCapReached(int requested) {
        McpEventLog log = eventLog();
        if (log != null) {
            log.info("resource-traversal: probe cap reached at " + MAX_TRAVERSAL_PROBES
                    + ", truncating coverage (" + requested + " distinct URIs queued)");
        }
    }

    /** Distinct discovered resource URIs (resources/list + inventory), so the prefix-sibling oracle
     *  and the static-URI families both work from one deduped set. */
    private List<String> discoveredResourceUris(ResourcesReadProbeRunner runner, HttpRequest baseline) {
        LinkedHashSet<String> uris = new LinkedHashSet<>(runner.discoverResourceUris(baseline));
        for (McpResourceDefinition resource : inventorySupplier.get().resources()) {
            if (resource.uri() != null) {
                uris.add(resource.uri());
            }
        }
        return new ArrayList<>(uris);
    }

    private static List<AuditIssue> buildIssues(HttpRequestResponse baseRequestResponse,
                                                List<ClassifiedFinding> findings,
                                                List<PrefixSiblingFinding> prefixSiblings) {
        String baseUrl = McpRequestDetector.extractBaseUrl(baseRequestResponse);
        List<AuditIssue> issues = new ArrayList<>();
        for (PathTraversalTier tier : PathTraversalTier.values()) {
            // PREFIX_SIBLING is reported from the error-differential oracle (below), never from the
            // signature-matched content findings, so it is skipped here.
            if (tier == PathTraversalTier.PREFIX_SIBLING) {
                continue;
            }
            List<TraversalHit> hits = hitsForTier(findings, tier);
            if (!hits.isEmpty()) {
                issues.add(buildIssue(baseUrl, tier, hits));
            }
        }
        if (!prefixSiblings.isEmpty()) {
            issues.add(buildPrefixSiblingIssue(baseUrl, prefixSiblings));
        }
        return issues;
    }

    private static AuditIssue buildPrefixSiblingIssue(String baseUrl,
                                                      List<PrefixSiblingFinding> findings) {
        List<String> findingLines = new ArrayList<>(findings.size());
        for (PrefixSiblingFinding finding : findings) {
            findingLines.add(finding.probedUri()
                    + " -> filesystem not-found for an out-of-root path (naive prefix-match bypass)");
        }
        IssueBodyBuilder builder = new IssueBodyBuilder()
                .paragraph(PREFIX_SIBLING_DETAIL_HEADER)
                .findings(findingLines);
        if (findings.size() > MAX_EVIDENCE_ENTRIES) {
            builder.paragraph("Showing first " + MAX_EVIDENCE_ENTRIES + " of " + findings.size()
                    + " total request/response pairs in the evidence panel.");
        }
        return AuditIssue.auditIssue(
                PREFIX_SIBLING_ISSUE_NAME,
                builder.build(),
                REMEDIATION,
                baseUrl,
                AuditIssueSeverity.MEDIUM, AuditIssueConfidence.FIRM,
                BACKGROUND, null, AuditIssueSeverity.MEDIUM,
                findings.stream().limit(MAX_EVIDENCE_ENTRIES)
                        .map(PrefixSiblingFinding::response).toList());
    }

    private static List<TraversalHit> hitsForTier(List<ClassifiedFinding> findings, PathTraversalTier tier) {
        List<TraversalHit> hits = new ArrayList<>();
        for (ClassifiedFinding finding : findings) {
            if (finding.tier() == tier) {
                hits.addAll(finding.evidence());
            }
        }
        return hits;
    }

    private static AuditIssue buildIssue(String baseUrl, PathTraversalTier tier, List<TraversalHit> hits) {
        return AuditIssue.auditIssue(
                issueName(tier),
                renderDetail(tier, hits),
                REMEDIATION,
                baseUrl,
                severity(tier), confidence(tier),
                BACKGROUND, null, severity(tier),
                cappedEvidence(hits)
        );
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

    private static String renderDetail(PathTraversalTier tier, List<TraversalHit> hits) {
        List<String> findingLines = new ArrayList<>(hits.size());
        for (TraversalHit hit : hits) {
            findingLines.add(hit.payload().uri() + " -> matched "
                    + FileSignatureLabels.describe(hit.payload().expectedSignatures()) + " content");
        }
        IssueBodyBuilder builder = new IssueBodyBuilder()
                .paragraph(detailHeader(tier))
                .findings(findingLines);
        if (hits.size() > MAX_EVIDENCE_ENTRIES) {
            builder.paragraph("Showing first " + MAX_EVIDENCE_ENTRIES + " of " + hits.size()
                    + " total request/response pairs in the evidence panel.");
        }
        return builder.build();
    }

    private static List<HttpRequestResponse> cappedEvidence(List<TraversalHit> hits) {
        return hits.stream()
                .limit(MAX_EVIDENCE_ENTRIES)
                .map(TraversalHit::response)
                .toList();
    }
}
