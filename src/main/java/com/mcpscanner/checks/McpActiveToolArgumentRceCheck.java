package com.mcpscanner.checks;

import burp.api.montoya.collaborator.CollaboratorClient;
import burp.api.montoya.collaborator.CollaboratorPayload;
import burp.api.montoya.collaborator.Interaction;
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
import com.mcpscanner.checks.ToolArgRcePayloads.RcePayloadTemplate;
import com.mcpscanner.checks.ToolsCallRceProbeRunner.FiredProbe;
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
import com.mcpscanner.mcp.McpRequestDetector;
import com.mcpscanner.scan.ScanInventory;

import java.time.Duration;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.function.Supplier;

public class McpActiveToolArgumentRceCheck extends ManagedActiveCheck
        implements SessionScopedCheck {

    private static final String ISSUE_NAME = "MCP Tool Argument Code Execution";
    static final int MAX_PROBES_PER_SCAN = 100;
    private static final int MAX_EVIDENCE_ENTRIES = 5;
    private static final int MAX_CONSECUTIVE_POLL_FAILURES = 3;
    // Escalating poll schedule with a ~5s total wall-clock deadline. The
    // intervals get longer because a late-arriving Collaborator interaction is
    // usually delayed by network/DNS jitter rather than the server still
    // computing, so back-loaded waits cost less and catch more.
    static final List<Duration> DEFAULT_POLL_SCHEDULE = List.of(
            Duration.ofMillis(250),
            Duration.ofMillis(500),
            Duration.ofMillis(1000),
            Duration.ofMillis(1500),
            Duration.ofMillis(1750)
    );

    private static final CheckDescriptor DESCRIPTOR = new CheckDescriptor(
            "tool-arg-rce",
            ISSUE_NAME,
            "A string argument passed to a tool reaches a server-side code evaluator, giving a "
                    + "client confirmed arbitrary code execution under the server's runtime identity.",
            AuditIssueSeverity.HIGH,
            ScanCheckType.PER_REQUEST,
            true,
            List.of(
                    "https://owasp.org/www-community/attacks/Code_Injection",
                    "https://nvd.nist.gov/vuln/detail/CVE-2025-49596",
                    "https://nvd.nist.gov/vuln/detail/CVE-2025-6514"
            ),
            "A tool argument value reaches a shell or interpreter, allowing out-of-band command or "
                    + "code execution (confirmed via Burp Collaborator).",
            List.of(
                    new Cwe(77, "Improper Neutralization of Special Elements used in a Command "
                            + "('Command Injection')"),
                    new Cwe(94, "Improper Control of Generation of Code ('Code Injection')"))
    );

    private static final String REMEDIATION = new IssueBodyBuilder()
            .paragraph("Never pass tool arguments into language-level evaluators (eval, exec, "
                    + "Function, system, backticks, child_process, Kernel#eval). Parse them against "
                    + "an explicit grammar or allow-list.")
            .paragraph("If dynamic evaluation is genuinely required, run it in a sandboxed process "
                    + "with no network, no filesystem, and a strict time limit, and validate the "
                    + "input against a constrained schema before invocation.")
            .build();

    private final Supplier<CollaboratorClient> collaboratorSupplier;
    private final Supplier<ScanInventory> selectedInventorySupplier;
    private final Sleeper sleeper;
    private final List<Duration> pollSchedule;
    private final HostDedup hostDedup = new HostDedup();

    public McpActiveToolArgumentRceCheck(ScanCheckSettings settings,
                                         McpEventLog eventLog,
                                         Supplier<CollaboratorClient> collaboratorSupplier) {
        this(settings, eventLog, collaboratorSupplier, ScanInventory::empty,
                Sleeper.SYSTEM, DEFAULT_POLL_SCHEDULE);
    }

    public McpActiveToolArgumentRceCheck(ScanCheckSettings settings,
                                         McpEventLog eventLog,
                                         Supplier<CollaboratorClient> collaboratorSupplier,
                                         Supplier<ScanInventory> selectedInventorySupplier) {
        this(settings, eventLog, collaboratorSupplier, selectedInventorySupplier,
                Sleeper.SYSTEM, DEFAULT_POLL_SCHEDULE);
    }

    public McpActiveToolArgumentRceCheck(ScanCheckSettings settings,
                                         McpEventLog eventLog,
                                         Supplier<CollaboratorClient> collaboratorSupplier,
                                         Supplier<ScanInventory> selectedInventorySupplier,
                                         Sleeper sleeper,
                                         List<Duration> pollSchedule) {
        super(settings, eventLog);
        this.collaboratorSupplier = collaboratorSupplier;
        this.selectedInventorySupplier = selectedInventorySupplier != null
                ? selectedInventorySupplier
                : ScanInventory::empty;
        this.sleeper = sleeper;
        this.pollSchedule = List.copyOf(pollSchedule);
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
        // Collaborator-backed probe battery only needs to run once per host. The result is
        // credential-independent (an injectable evaluator fires regardless of bearer), so a plain
        // host key is sufficient.
        if (!hostDedup.tryClaim(baseRequestResponse.request())) {
            ScanCheckLogging.decisionSkipped(eventLog(), descriptor().id(), "already probed host");
            return emptyResult();
        }

        Set<String> selectedToolNames = SelectedToolsFilter.selectedToolNames(selectedInventorySupplier);
        if (selectedToolNames.isEmpty()) {
            logSkippedNoSelection();
            return emptyResult();
        }

        HttpRequest baseline = baseRequestResponse.request();
        ReachabilityTrackingHttp trackedHttp = new ReachabilityTrackingHttp(http);
        ToolsCallRceProbeRunner runner = new ToolsCallRceProbeRunner(trackedHttp);
        List<DiscoveredTool> selectedTools =
                SelectedToolsFilter.retainSelected(runner.discoverTools(baseline), selectedToolNames);
        if (selectedTools.isEmpty()) {
            releaseIfUnreached(baseRequestResponse, trackedHttp);
            return emptyResult();
        }
        List<ToolArgument> codeArguments = runner.findCodeArguments(selectedTools);
        if (codeArguments.isEmpty()) {
            return emptyResult();
        }

        CollaboratorClient client = obtainClient();
        if (client == null) {
            // Collaborator being unavailable is a transient/environmental condition, not a clean
            // negative from the server — release so a later insertion point retries once it returns.
            hostDedup.releaseIfHttpLayerErrored(baseRequestResponse.request());
            return emptyResult();
        }

        List<FiredProbe> probes = fireAllProbes(runner, baseline, codeArguments, client);
        if (probes.isEmpty()) {
            releaseIfUnreached(baseRequestResponse, trackedHttp);
            return emptyResult();
        }

        List<Interaction> interactions = pollForInteractions(client, probes);
        if (interactions.isEmpty()) {
            return emptyResult();
        }

        List<AuditIssue> issues = buildIssues(baseRequestResponse, probes, interactions);
        return AuditResult.auditResult(issues);
    }

    private void releaseIfUnreached(HttpRequestResponse baseRequestResponse,
                                    ReachabilityTrackingHttp trackedHttp) {
        // Release the claim only when the battery never reached the server (every probe failed at
        // the HTTP layer) so a later insertion point retries; a clean negative from a reachable
        // server keeps the claim so the battery does not re-run per insertion point.
        if (!trackedHttp.reachedServer()) {
            hostDedup.releaseIfHttpLayerErrored(baseRequestResponse.request());
        }
    }

    private void logSkippedNoSelection() {
        McpEventLog log = eventLog();
        if (log != null) {
            log.info("tool-arg-rce: no tools selected by user, skipping");
        }
    }

    private CollaboratorClient obtainClient() {
        if (collaboratorSupplier == null) {
            logCollaboratorUnavailable("supplier is null");
            return null;
        }
        try {
            CollaboratorClient client = collaboratorSupplier.get();
            if (client == null) {
                logCollaboratorUnavailable("supplier returned null");
            }
            return client;
        } catch (RuntimeException ex) {
            logCollaboratorUnavailable("supplier threw " + ex.getClass().getSimpleName());
            return null;
        }
    }

    private void logCollaboratorUnavailable(String reason) {
        McpEventLog log = eventLog();
        if (log != null) {
            log.info("tool-arg-rce: Collaborator unavailable, skipping (" + reason + ")");
        }
    }

    private List<FiredProbe> fireAllProbes(ToolsCallRceProbeRunner runner,
                                           HttpRequest baseline,
                                           List<ToolArgument> codeArguments,
                                           CollaboratorClient client) {
        List<FiredProbe> probes = new ArrayList<>();
        int templateCount = ToolArgRcePayloads.all().size();
        int distinctTools = (int) codeArguments.stream().map(ToolArgument::tool).distinct().count();
        for (ToolArgument argument : codeArguments) {
            for (RcePayloadTemplate payload : ToolArgRcePayloads.all()) {
                if (probes.size() >= MAX_PROBES_PER_SCAN) {
                    logProbeCapReached(distinctTools, codeArguments.size(), templateCount);
                    return probes;
                }
                CollaboratorPayload mintedPayload;
                try {
                    mintedPayload = client.generatePayload();
                } catch (RuntimeException ex) {
                    logPayloadGenerationFailed(ex);
                    return probes;
                }
                String subdomain = mintedPayload.toString();
                String interactionId = mintedPayload.id().toString();
                probes.add(runner.fire(baseline, argument, payload, subdomain, interactionId));
            }
        }
        return probes;
    }

    private void logPayloadGenerationFailed(RuntimeException ex) {
        McpEventLog log = eventLog();
        if (log != null) {
            log.info("tool-arg-rce: payload generation failed ("
                    + ex.getClass().getSimpleName() + ": " + ex.getMessage()
                    + "); aborting probe loop");
        }
    }

    private void logProbeCapReached(int distinctTools, int codeArguments, int templateCount) {
        McpEventLog log = eventLog();
        if (log != null) {
            log.info("tool-arg-rce: probe cap reached at " + MAX_PROBES_PER_SCAN
                    + ", skipping remaining (" + distinctTools + " tools x "
                    + codeArguments + " args x " + templateCount + " templates queued)");
        }
    }

    private List<Interaction> pollForInteractions(CollaboratorClient client, List<FiredProbe> probes) {
        Set<String> outstandingIds = outstandingInteractionIds(probes);
        Map<String, Interaction> matched = new LinkedHashMap<>();
        int consecutiveFailures = 0;
        for (Duration interval : pollSchedule) {
            sleeper.sleep(interval);
            List<Interaction> latest;
            try {
                List<Interaction> raw = client.getAllInteractions();
                latest = raw != null ? raw : List.of();
                consecutiveFailures = 0;
            } catch (RuntimeException ex) {
                logPollFailure(ex);
                if (++consecutiveFailures >= MAX_CONSECUTIVE_POLL_FAILURES) {
                    break;
                }
                continue;
            }
            for (Interaction interaction : latest) {
                String id = interaction.id().toString();
                if (outstandingIds.contains(id) && !matched.containsKey(id)) {
                    matched.put(id, interaction);
                }
            }
            if (matched.size() == outstandingIds.size()) {
                break;
            }
        }
        return new ArrayList<>(matched.values());
    }

    private static Set<String> outstandingInteractionIds(List<FiredProbe> probes) {
        Set<String> ids = new LinkedHashSet<>(probes.size());
        for (FiredProbe probe : probes) {
            ids.add(probe.interactionId());
        }
        return ids;
    }

    private void logPollFailure(RuntimeException ex) {
        McpEventLog log = eventLog();
        if (log != null) {
            log.info("tool-arg-rce: Collaborator poll failed ("
                    + ex.getClass().getSimpleName() + ": " + ex.getMessage() + ")");
        }
    }

    private static List<AuditIssue> buildIssues(HttpRequestResponse baseRequestResponse,
                                                List<FiredProbe> probes,
                                                List<Interaction> interactions) {
        Map<String, List<ConfirmedHit>> grouped = groupConfirmedHits(probes, interactions);
        if (grouped.isEmpty()) {
            return List.of();
        }
        String baseUrl = McpRequestDetector.extractBaseUrl(baseRequestResponse);
        List<AuditIssue> issues = new ArrayList<>(grouped.size());
        for (Map.Entry<String, List<ConfirmedHit>> entry : grouped.entrySet()) {
            issues.add(buildIssue(baseUrl, entry.getKey(), entry.getValue()));
        }
        return issues;
    }

    private static Map<String, List<ConfirmedHit>> groupConfirmedHits(List<FiredProbe> probes,
                                                                      List<Interaction> interactions) {
        Map<String, List<ConfirmedHit>> grouped = new LinkedHashMap<>();
        for (FiredProbe probe : probes) {
            for (Interaction interaction : interactions) {
                if (interaction.id().toString().equals(probe.interactionId())) {
                    String key = issueKey(probe);
                    grouped.computeIfAbsent(key, ignored -> new ArrayList<>())
                            .add(new ConfirmedHit(probe, interaction));
                    break;
                }
            }
        }
        return grouped;
    }

    private static String issueKey(FiredProbe probe) {
        return probe.argument().tool().name() + "::" + probe.argument().name();
    }

    private static AuditIssue buildIssue(String baseUrl, String issueKey, List<ConfirmedHit> hits) {
        return AuditIssue.auditIssue(
                ISSUE_NAME,
                renderDetail(issueKey, hits),
                REMEDIATION,
                baseUrl,
                AuditIssueSeverity.HIGH, confidenceFor(hits),
                IssueMetadataRenderer.background(
                        DESCRIPTOR.issueBackground(), DESCRIPTOR.cwes(), DESCRIPTOR.references()),
                null, AuditIssueSeverity.HIGH,
                cappedEvidence(hits)
        );
    }

    // A full HTTP callback to the unique payload host is unequivocal code
    // execution (CERTAIN). A DNS-only lookup is strong but has narrow alternative
    // explanations (shared resolver, DNS prefetch), so it caps the confidence at
    // FIRM. A group with any HTTP hit is therefore CERTAIN; an all-DNS group FIRM.
    private static AuditIssueConfidence confidenceFor(List<ConfirmedHit> hits) {
        return hasHttpInteraction(hits) ? AuditIssueConfidence.CERTAIN : AuditIssueConfidence.FIRM;
    }

    private static boolean hasHttpInteraction(List<ConfirmedHit> hits) {
        return hits.stream().anyMatch(hit -> hit.interaction().type()
                == burp.api.montoya.collaborator.InteractionType.HTTP);
    }

    private static String renderDetail(String issueKey, List<ConfirmedHit> hits) {
        List<String> hitLines = new ArrayList<>(hits.size());
        for (ConfirmedHit hit : hits) {
            FiredProbe probe = hit.probe();
            hitLines.add(probe.payload().language() + " payload triggered a "
                    + callbackKind(hit.interaction().type()) + " callback: "
                    + probe.payload().render(probe.collaboratorSubdomain()));
        }
        IssueBodyBuilder builder = new IssueBodyBuilder()
                .paragraph("A string argument passed to this tool was executed as server-side code. "
                        + "The server made an out-of-band callback to a scanner-controlled host, "
                        + "evidencing code execution under the server's runtime identity.")
                .paragraph(evidenceStrengthNote(hits))
                .paragraph("Tool argument: " + issueKey)
                .findings(hitLines);
        if (hits.size() > MAX_EVIDENCE_ENTRIES) {
            builder.paragraph("Showing first " + MAX_EVIDENCE_ENTRIES + " of " + hits.size()
                    + " confirmed hits in the evidence panel; " + (hits.size() - MAX_EVIDENCE_ENTRIES)
                    + " additional hits not shown.");
        }
        return builder
                .build();
    }

    private static String evidenceStrengthNote(List<ConfirmedHit> hits) {
        if (hasHttpInteraction(hits)) {
            return "A full HTTP callback reached the unique payload host, so this is confirmed "
                    + "arbitrary code execution.";
        }
        return "Only a DNS lookup of the unique payload host was observed (no HTTP callback). "
                + "This is strong evidence of code execution, but a DNS-only interaction has narrow "
                + "alternative explanations (a shared resolver or DNS prefetch), so the confidence is "
                + "reported as Firm rather than Certain.";
    }

    private static String callbackKind(burp.api.montoya.collaborator.InteractionType type) {
        return switch (type) {
            case DNS -> "DNS";
            case HTTP -> "HTTP";
            default -> "network";
        };
    }

    private static List<HttpRequestResponse> cappedEvidence(List<ConfirmedHit> hits) {
        return hits.stream()
                .limit(MAX_EVIDENCE_ENTRIES)
                .map(hit -> hit.probe().response())
                .toList();
    }

    private static AuditResult emptyResult() {
        return AuditResult.auditResult(List.of());
    }

    private record ConfirmedHit(FiredProbe probe, Interaction interaction) {}
}
