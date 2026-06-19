package com.mcpscanner.checks;

import burp.api.montoya.http.HttpService;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.scanner.AuditResult;
import burp.api.montoya.scanner.ConsolidationAction;
import burp.api.montoya.scanner.audit.issues.AuditIssue;
import burp.api.montoya.scanner.audit.issues.AuditIssueSeverity;
import burp.api.montoya.scanner.scancheck.ScanCheckType;
import com.mcpscanner.checks.content.ContentFinding;
import com.mcpscanner.checks.content.ContentFindingIssueBuilder;
import com.mcpscanner.checks.content.ContentRule;
import com.mcpscanner.checks.content.ContentRuleContext;
import com.mcpscanner.checks.content.ContentRuleEngine;
import com.mcpscanner.checks.content.ContentRules;
import com.mcpscanner.checks.content.InspectedField;
import com.mcpscanner.checks.content.ResponseBodyContentExtractor;
import com.mcpscanner.checks.registry.CheckDescriptor;
import com.mcpscanner.checks.registry.ContentRuleDescriptor;
import com.mcpscanner.checks.registry.ManagedPassiveCheck;
import com.mcpscanner.checks.registry.ScanCheckSettings;
import com.mcpscanner.logging.McpEventLog;
import com.mcpscanner.mcp.McpRequestDetector;
import com.mcpscanner.mcp.McpRequestDetector.ResponseContentKind;

import java.util.List;
import java.util.Objects;

/**
 * Passive scan check that inspects HTTP responses to MCP runtime-output JSON-RPC methods
 * ({@code tools/call}, {@code resources/read}, {@code prompts/get}), runs a high-precision
 * secret-detection rule subset over the spec-defined textual response fields, and emits
 * findings as {@link AuditIssue}s.
 *
 * <p>Complements the discovery-time {@code JsonRpcDiscoveryResponseScanner}: that scanner
 * inspects discovery metadata, this one inspects the runtime output a tool, resource, or
 * prompt returns to the caller — the most realistic credential-leak surface. The two are
 * disjoint by method set (enforced in
 * {@link McpRequestDetector#classifyResponseContent(HttpRequestResponse)}) so a single
 * exchange never double-fires. The rule subset deliberately excludes low-precision detectors
 * (email, private IP, credit card, icon) that fire legitimately on real tool output.
 */
public final class JsonRpcResponseContentScanner extends ManagedPassiveCheck {

    public static final CheckDescriptor DESCRIPTOR = new CheckDescriptor(
            ContentRuleDescriptor.RESPONSE_CONTENT_ID,
            "MCP Response Content Scanner",
            "Flags high-confidence secrets — cloud keys, tokens, and private keys — returned "
                    + "in MCP runtime output: tool-call results, resource contents, and prompt "
                    + "messages. A credential leaked in a response is exposed to any caller that "
                    + "triggers it. Detection is limited to high-confidence formats to minimise "
                    + "false positives on legitimate output.",
            AuditIssueSeverity.HIGH,
            ScanCheckType.PER_HOST,
            true,
            List.of(
                    "https://modelcontextprotocol.io/docs/tutorials/security/security_best_practices"
            )
    );

    private final ContentRuleEngine engine;

    public JsonRpcResponseContentScanner(ScanCheckSettings settings, McpEventLog eventLog) {
        this(settings, ContentRules.highPrecisionSecrets(), eventLog);
    }

    public JsonRpcResponseContentScanner(ScanCheckSettings settings, List<ContentRule> rules) {
        this(settings, rules, null);
    }

    private JsonRpcResponseContentScanner(ScanCheckSettings settings,
                                          List<ContentRule> rules,
                                          McpEventLog eventLog) {
        super(settings, eventLog);
        this.engine = new ContentRuleEngine(Objects.requireNonNull(rules, "rules must not be null"));
    }

    @Override
    public CheckDescriptor descriptor() {
        return DESCRIPTOR;
    }

    @Override
    protected AuditResult runCheck(HttpRequestResponse baseRequestResponse) {
        ResponseContentKind kind = McpRequestDetector.classifyResponseContent(baseRequestResponse);
        if (kind == ResponseContentKind.OTHER) {
            return AuditResult.auditResult(List.of());
        }
        List<InspectedField> fields = ResponseBodyContentExtractor.extract(kind, baseRequestResponse);
        HttpService host = baseRequestResponse.request().httpService();
        List<ContentFinding> findings = engine.run(List.of(
                ContentRuleContext.forResponseBody(McpRequestDetector.baseUrl(host), fields, host)));
        return AuditResult.auditResult(ContentFindingIssueBuilder.buildAll(
                findings, host, baseRequestResponse, ContentFindingIssueBuilder.RESPONSE_SOURCE));
    }

    @Override
    public ConsolidationAction consolidateIssues(AuditIssue existingIssue, AuditIssue newIssue) {
        return existingIssue.name().equals(newIssue.name())
                && existingIssue.baseUrl().equals(newIssue.baseUrl())
                ? ConsolidationAction.KEEP_EXISTING
                : ConsolidationAction.KEEP_BOTH;
    }
}
