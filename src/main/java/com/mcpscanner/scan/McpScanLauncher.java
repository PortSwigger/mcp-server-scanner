package com.mcpscanner.scan;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.Range;
import burp.api.montoya.logging.Logging;
import burp.api.montoya.scanner.AuditConfiguration;
import burp.api.montoya.scanner.BuiltInAuditConfiguration;
import burp.api.montoya.scanner.Scanner;
import burp.api.montoya.scanner.audit.Audit;
import burp.api.montoya.scanner.audit.issues.AuditIssue;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.mcpscanner.logging.McpEventLog;
import com.mcpscanner.mcp.McpObjectMapper;
import com.mcpscanner.mcp.McpPromptDefinition;
import com.mcpscanner.mcp.McpResourceDefinition;
import com.mcpscanner.mcp.McpResourceTemplateDefinition;
import com.mcpscanner.mcp.McpToolDefinition;
import com.mcpscanner.mcp.PromptArgument;
import com.mcpscanner.scan.JsonRpcRequestBuilder.RequestWithOffsets;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.function.Supplier;

import static burp.api.montoya.core.Range.range;

public class McpScanLauncher {

    private final MontoyaApi api;
    private final Scanner scanner;
    private final Logging logging;
    private final McpEventLog eventLog;
    private final JsonRpcRequestBuilder requestBuilder;
    private final Supplier<ScanStartContext> contextSupplier;
    private final List<ScanStartCheck> scanStartChecks;
    private final CopyOnWriteArrayList<Audit> activeAudits = new CopyOnWriteArrayList<>();

    public McpScanLauncher(Scanner scanner, Logging logging, JsonRpcRequestBuilder requestBuilder) {
        this(scanner, logging, McpEventLog.noop(), requestBuilder);
    }

    public McpScanLauncher(Scanner scanner, Logging logging, McpEventLog eventLog,
                           JsonRpcRequestBuilder requestBuilder) {
        this(null, scanner, logging, eventLog, requestBuilder, null, List.of());
    }

    public McpScanLauncher(MontoyaApi api, McpEventLog eventLog, JsonRpcRequestBuilder requestBuilder,
                           Supplier<ScanStartContext> contextSupplier,
                           List<ScanStartCheck> scanStartChecks) {
        this(api, api.scanner(), api.logging(), eventLog, requestBuilder, contextSupplier, scanStartChecks);
    }

    private McpScanLauncher(MontoyaApi api, Scanner scanner, Logging logging, McpEventLog eventLog,
                            JsonRpcRequestBuilder requestBuilder,
                            Supplier<ScanStartContext> contextSupplier,
                            List<ScanStartCheck> scanStartChecks) {
        this.api = api;
        this.scanner = scanner;
        this.logging = logging;
        this.eventLog = eventLog != null ? eventLog : McpEventLog.noop();
        this.requestBuilder = requestBuilder;
        this.contextSupplier = contextSupplier;
        this.scanStartChecks = List.copyOf(scanStartChecks);
    }

    public Audit launchScan(String endpoint, ScanInventory inventory, Map<String, String> headers) {
        runScanStartChecks();
        List<PreparedRequest> prepared = prepareRequests(endpoint, inventory, headers);
        Audit audit = scanner.startAudit(
                AuditConfiguration.auditConfiguration(BuiltInAuditConfiguration.LEGACY_ACTIVE_AUDIT_CHECKS));
        activeAudits.add(audit);
        logAuditSummary(prepared);
        for (PreparedRequest entry : prepared) {
            recordAuditEntry(audit, entry);
        }
        return audit;
    }

    public void cancelActiveScans() {
        for (Audit audit : activeAudits) {
            tryDeleteAudit(audit);
        }
        activeAudits.clear();
    }

    /**
     * Drops retained {@link Audit} references without cancelling them, so a long-lived
     * Burp session that repeatedly connects/scans/disconnects does not accumulate live
     * audit results for the whole session. Wired to disconnect — a normal disconnect must
     * not kill an in-flight scan (cancelling is {@link #cancelActiveScans()}'s job at
     * shutdown / terminal auth failure); the references are merely released so Burp can
     * GC each audit once it is done with it.
     */
    public void clearActiveScans() {
        activeAudits.clear();
    }

    private void tryDeleteAudit(Audit audit) {
        try {
            audit.delete();
        } catch (RuntimeException e) {
            eventLog.warn("Audit cancel failed: " + e.getClass().getSimpleName());
        }
    }

    private void runScanStartChecks() {
        if (scanStartChecks.isEmpty() || api == null || contextSupplier == null) {
            return;
        }
        ScanStartContext context = contextSupplier.get();
        if (context == null) {
            return;
        }
        for (ScanStartCheck check : scanStartChecks) {
            invokeScanStartCheck(check, context);
        }
    }

    private void invokeScanStartCheck(ScanStartCheck check, ScanStartContext context) {
        try {
            List<AuditIssue> issues = check.runOnceForSession(context, api.http());
            if (issues == null) {
                return;
            }
            for (AuditIssue issue : issues) {
                api.siteMap().add(issue);
            }
            if (!issues.isEmpty()) {
                eventLog.info("Scan-start check emitted " + pluralise(issues.size(), "issue")
                        + " to site map");
            }
        } catch (RuntimeException e) {
            String reason = e.getClass().getSimpleName()
                    + (e.getMessage() != null ? ": " + e.getMessage() : "");
            if (logging != null) {
                logging.logToError("Scan-start check failed: " + reason);
            }
            eventLog.warn("Scan-start check failed: " + reason);
        }
    }

    private void logAuditSummary(List<PreparedRequest> prepared) {
        int requests = 0;
        int insertionPoints = 0;
        for (PreparedRequest entry : prepared) {
            List<InsertionPointOffset> offsets = entry.result.offsets();
            if (!offsets.isEmpty()) {
                requests++;
                insertionPoints += offsets.size();
            }
        }
        eventLog.info("Audit started — " + pluralise(requests, "request")
                + ", " + pluralise(insertionPoints, "insertion point"));
    }

    private static String pluralise(int count, String singular) {
        return count + " " + singular + (count == 1 ? "" : "s");
    }

    private List<PreparedRequest> prepareRequests(String endpoint, ScanInventory inventory,
                                                  Map<String, String> headers) {
        List<PreparedRequest> entries = new ArrayList<>();
        for (McpToolDefinition tool : inventory.tools()) {
            entries.add(prepareTool(endpoint, tool, headers));
        }
        for (McpResourceDefinition resource : inventory.resources()) {
            entries.add(prepareResource(endpoint, resource, headers));
        }
        for (McpResourceTemplateDefinition template : inventory.resourceTemplates()) {
            entries.add(prepareResourceTemplate(endpoint, template, headers));
        }
        for (McpPromptDefinition prompt : inventory.prompts()) {
            entries.add(preparePrompt(endpoint, prompt, headers));
        }
        return entries;
    }

    private PreparedRequest prepareTool(String endpoint, McpToolDefinition tool, Map<String, String> headers) {
        String argumentsJson = JsonSchemaDefaults.buildDefaultArgumentsJson(tool.inputSchema());
        RequestWithOffsets result = requestBuilder.build(endpoint, tool.name(), argumentsJson, headers);
        return new PreparedRequest(result, "tool", tool.name());
    }

    private PreparedRequest prepareResource(String endpoint, McpResourceDefinition resource,
                                            Map<String, String> headers) {
        RequestWithOffsets result = requestBuilder.buildResourceRead(endpoint, resource.uri(), headers);
        return new PreparedRequest(result, "resource", resource.uri());
    }

    private PreparedRequest prepareResourceTemplate(String endpoint, McpResourceTemplateDefinition template,
                                                    Map<String, String> headers) {
        RequestWithOffsets result = requestBuilder.buildResourceTemplateRead(endpoint, template.uriTemplate(), headers);
        return new PreparedRequest(result, "resource template", template.uriTemplate());
    }

    private PreparedRequest preparePrompt(String endpoint, McpPromptDefinition prompt, Map<String, String> headers) {
        String argumentsJson = buildDefaultPromptArguments(prompt);
        RequestWithOffsets result = requestBuilder.buildPromptGet(endpoint, prompt.name(), argumentsJson, headers);
        return new PreparedRequest(result, "prompt", prompt.name());
    }

    private void recordAuditEntry(Audit audit, PreparedRequest entry) {
        List<Range> ranges = toRanges(entry.result.offsets());
        if (ranges.isEmpty()) {
            logging.logToOutput("Skipped " + entry.kindLabel + " with no fuzzable input: " + entry.identifier);
            eventLog.warn("Skipped " + entry.kindLabel + " with no fuzzable input: " + entry.identifier);
            return;
        }
        audit.addRequest(entry.result.request(), ranges);
        logging.logToOutput("Added " + entry.kindLabel + " to audit: " + entry.identifier
                + " with " + ranges.size() + " insertion points");
    }

    private String buildDefaultPromptArguments(McpPromptDefinition prompt) {
        try {
            Map<String, String> arguments = new LinkedHashMap<>();
            if (prompt.arguments() != null) {
                for (PromptArgument argument : prompt.arguments()) {
                    arguments.put(argument.name(), "test");
                }
            }
            return McpObjectMapper.INSTANCE.writeValueAsString(arguments);
        } catch (JsonProcessingException e) {
            throw new IllegalStateException("Failed to serialise prompt arguments", e);
        }
    }

    private List<Range> toRanges(List<InsertionPointOffset> offsets) {
        return offsets.stream()
                .map(offset -> range(offset.startInclusive(), offset.endExclusive()))
                .toList();
    }

    private record PreparedRequest(RequestWithOffsets result, String kindLabel, String identifier) {}
}
