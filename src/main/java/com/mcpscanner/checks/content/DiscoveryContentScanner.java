package com.mcpscanner.checks.content;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.HttpService;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.scanner.audit.issues.AuditIssue;
import com.mcpscanner.checks.registry.ContentRuleDescriptor;
import com.mcpscanner.checks.registry.ScanCheckSettings;
import com.mcpscanner.client.DiscoveryResultObserver;
import com.mcpscanner.mcp.McpPromptDefinition;
import com.mcpscanner.mcp.McpResourceDefinition;
import com.mcpscanner.mcp.McpResourceTemplateDefinition;
import com.mcpscanner.mcp.McpToolDefinition;
import com.mcpscanner.mcp.ServerMetadata;

import java.util.List;
import java.util.Objects;

/**
 * Connect-time sensitive-content scanner. Runs the {@link ContentRuleEngine} over the
 * discovered metadata and emits {@link AuditIssue}s via {@code siteMap().add(...)}.
 *
 * <p>Findings pass through a shared {@link ContentFindingDedup} before issue building so the
 * same secret is not also re-reported by the passive {@code JsonRpcDiscoveryResponseScanner}
 * (which sees the same connect-time discovery responses). Whichever surface fires first for a
 * given {@code (ruleId, matchedValue, host)} wins.
 */
public final class DiscoveryContentScanner implements DiscoveryResultObserver {

    private final ContentRuleEngine engine;
    private final ScanCheckSettings settings;
    private final MontoyaApi api;
    private final ContentFindingDedup dedup;

    public DiscoveryContentScanner(List<ContentRule> rules, ScanCheckSettings settings, MontoyaApi api) {
        this(rules, settings, api, new ContentFindingDedup());
    }

    public DiscoveryContentScanner(List<ContentRule> rules,
                                   ScanCheckSettings settings,
                                   MontoyaApi api,
                                   ContentFindingDedup dedup) {
        this.engine = new ContentRuleEngine(Objects.requireNonNull(rules, "rules must not be null"));
        this.settings = Objects.requireNonNull(settings, "settings must not be null");
        this.api = Objects.requireNonNull(api, "api must not be null");
        this.dedup = Objects.requireNonNull(dedup, "dedup must not be null");
    }

    @Override
    public void onDiscovery(ServerMetadata serverMetadata,
                            List<McpToolDefinition> tools,
                            List<McpResourceDefinition> resources,
                            List<McpResourceTemplateDefinition> resourceTemplates,
                            List<McpPromptDefinition> prompts,
                            HttpService host) {
        // No HTTP-level evidence to attach: langchain4j's transport handles the initialize
        // exchange internally and the raw request/response is not exposed, so the scan falls
        // back to a host-only issue without an evidence record.
        scan(new DiscoveredContent(serverMetadata, tools, resources, resourceTemplates, prompts), host, null);
    }

    public void scan(DiscoveredContent content, HttpService host, HttpRequestResponse initializeEvidence) {
        if (content == null || !settings.isEnabled(ContentRuleDescriptor.MASTER_ID, true)) {
            return;
        }
        ContentRuleContext context = ContentRuleContext.forDiscoveryBundle(baseUrl(host), content, host);
        List<ContentFinding> findings = dedup.claimUnseen(engine.run(List.of(context)), host);
        for (AuditIssue issue : ContentFindingIssueBuilder.buildAll(findings, host, initializeEvidence)) {
            api.siteMap().add(issue);
        }
    }

    private static String baseUrl(HttpService host) {
        if (host == null) {
            return "";
        }
        String scheme = host.secure() ? "https" : "http";
        int port = host.port();
        boolean defaultPort = (host.secure() && port == 443) || (!host.secure() && port == 80);
        String authority = defaultPort ? host.host() : host.host() + ":" + port;
        return scheme + "://" + authority;
    }
}
