package com.mcpscanner.checks;

import burp.api.montoya.http.HttpService;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.scanner.AuditResult;
import burp.api.montoya.scanner.ConsolidationAction;
import burp.api.montoya.scanner.audit.issues.AuditIssue;
import burp.api.montoya.scanner.audit.issues.AuditIssueSeverity;
import burp.api.montoya.scanner.scancheck.ScanCheckType;
import com.mcpscanner.checks.content.ContentFinding;
import com.mcpscanner.checks.content.ContentFindingDedup;
import com.mcpscanner.checks.content.ContentFindingIssueBuilder;
import com.mcpscanner.checks.content.ContentRule;
import com.mcpscanner.checks.content.ContentRuleContext;
import com.mcpscanner.checks.content.ContentRuleEngine;
import com.mcpscanner.checks.content.ContentRules;
import com.mcpscanner.checks.content.DiscoveredContent;
import com.mcpscanner.checks.content.JsonRpcDiscoveredContentTranslator;
import com.mcpscanner.checks.registry.CheckDescriptor;
import com.mcpscanner.checks.registry.ContentRuleDescriptor;
import com.mcpscanner.checks.registry.ManagedPassiveCheck;
import com.mcpscanner.checks.registry.ScanCheckSettings;
import com.mcpscanner.logging.McpEventLog;
import com.mcpscanner.mcp.McpRequestDetector;
import com.mcpscanner.mcp.McpRequestDetector.DiscoveryResponseKind;

import java.util.List;
import java.util.Objects;

/**
 * Passive scan check that inspects HTTP responses to MCP discovery JSON-RPC methods
 * ({@code tools/list}, {@code resources/list}, {@code prompts/list}, {@code initialize}),
 * runs the shared {@link ContentRuleEngine} against the MCP-specified textual fields,
 * and emits findings as {@link AuditIssue}s so they appear in audit reports.
 *
 * <p>Three layers of defense-in-depth filtering before a rule runs:
 *
 * <ol>
 *   <li><strong>HTTP-layer</strong> + <strong>MCP-layer</strong> — delegated to
 *       {@link McpRequestDetector#classifyDiscoveryResponse(HttpRequestResponse)}, which
 *       requires the request to be a well-formed POST application/json JSON-RPC 2.0
 *       envelope whose {@code method} matches one of the four discovery methods AND the
 *       response to be a 200 with a result envelope of the expected shape.</li>
 *   <li><strong>Field-scoping</strong> — {@link JsonRpcDiscoveredContentTranslator}
 *       populates {@link DiscoveredContent} with ONLY the spec-defined textual fields
 *       ({@code name}/{@code title}/{@code description}/{@code uri}/{@code mimeType}/
 *       {@code icons[].src}/{@code serverInfo}/{@code instructions}/{@code capabilities}
 *       keys). User-controlled metadata such as a tool's {@code inputSchema} (and any
 *       placeholder {@code default} values inside it) is deliberately dropped so secret
 *       regexes cannot match against argument-schema noise.</li>
 * </ol>
 */
public final class JsonRpcDiscoveryResponseScanner extends ManagedPassiveCheck {

    public static final CheckDescriptor DESCRIPTOR = new CheckDescriptor(
            ContentRuleDescriptor.MASTER_ID,
            "MCP Discovery Content Scanner",
            "Flags secrets, credentials, and PII exposed in the server's MCP discovery "
                    + "metadata — serverInfo, and the descriptions, names, URIs, and icon "
                    + "links of tools, resources, and prompts. This metadata is returned to "
                    + "every client, so anything sensitive embedded here is effectively "
                    + "published. Only spec-defined text fields are inspected.",
            AuditIssueSeverity.MEDIUM,
            ScanCheckType.PER_HOST,
            true,
            List.of(
                    "https://modelcontextprotocol.io/specification/2025-11-25/basic/index#icons",
                    "https://modelcontextprotocol.io/docs/tutorials/security/security_best_practices"
            )
    );

    private final ContentRuleEngine engine;
    private final ContentFindingDedup dedup;

    public JsonRpcDiscoveryResponseScanner(ScanCheckSettings settings, McpEventLog eventLog) {
        this(settings, ContentRules.all(), eventLog, new ContentFindingDedup());
    }

    public JsonRpcDiscoveryResponseScanner(ScanCheckSettings settings,
                                           McpEventLog eventLog,
                                           ContentFindingDedup dedup) {
        this(settings, ContentRules.all(), eventLog, dedup);
    }

    public JsonRpcDiscoveryResponseScanner(ScanCheckSettings settings, List<ContentRule> rules) {
        this(settings, rules, null, new ContentFindingDedup());
    }

    public JsonRpcDiscoveryResponseScanner(ScanCheckSettings settings,
                                           List<ContentRule> rules,
                                           ContentFindingDedup dedup) {
        this(settings, rules, null, dedup);
    }

    private JsonRpcDiscoveryResponseScanner(ScanCheckSettings settings,
                                            List<ContentRule> rules,
                                            McpEventLog eventLog,
                                            ContentFindingDedup dedup) {
        super(settings, eventLog);
        this.engine = new ContentRuleEngine(Objects.requireNonNull(rules, "rules must not be null"));
        this.dedup = Objects.requireNonNull(dedup, "dedup must not be null");
    }

    @Override
    public CheckDescriptor descriptor() {
        return DESCRIPTOR;
    }

    @Override
    protected AuditResult runCheck(HttpRequestResponse baseRequestResponse) {
        DiscoveryResponseKind kind = McpRequestDetector.classifyDiscoveryResponse(baseRequestResponse);
        if (kind == DiscoveryResponseKind.OTHER) {
            return AuditResult.auditResult(List.of());
        }
        DiscoveredContent content = JsonRpcDiscoveredContentTranslator.translate(
                kind, baseRequestResponse.response().bodyToString());
        HttpService host = baseRequestResponse.request().httpService();
        List<ContentFinding> findings = dedup.claimUnseen(engine.run(List.of(
                ContentRuleContext.forDiscoveryBundle(McpRequestDetector.baseUrl(host), content, host))), host);
        return AuditResult.auditResult(
                ContentFindingIssueBuilder.buildAll(findings, host, baseRequestResponse));
    }

    @Override
    public ConsolidationAction consolidateIssues(AuditIssue existingIssue, AuditIssue newIssue) {
        return existingIssue.name().equals(newIssue.name())
                && existingIssue.baseUrl().equals(newIssue.baseUrl())
                ? ConsolidationAction.KEEP_EXISTING
                : ConsolidationAction.KEEP_BOTH;
    }
}
