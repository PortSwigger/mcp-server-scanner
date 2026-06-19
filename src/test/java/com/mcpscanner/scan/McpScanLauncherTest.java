package com.mcpscanner.scan;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.Range;
import burp.api.montoya.http.Http;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.logging.Logging;
import burp.api.montoya.scanner.AuditConfiguration;
import burp.api.montoya.scanner.Scanner;
import burp.api.montoya.scanner.audit.Audit;
import burp.api.montoya.scanner.audit.issues.AuditIssue;
import burp.api.montoya.scanner.audit.issues.AuditIssueConfidence;
import burp.api.montoya.scanner.audit.issues.AuditIssueSeverity;
import burp.api.montoya.sitemap.SiteMap;
import com.mcpscanner.logging.McpEventLog;
import com.mcpscanner.mcp.McpPromptDefinition;
import com.mcpscanner.mcp.McpResourceDefinition;
import com.mcpscanner.mcp.McpResourceTemplateDefinition;
import com.mcpscanner.mcp.McpToolDefinition;
import com.mcpscanner.mcp.PromptArgument;
import com.mcpscanner.testutil.MontoyaTestFactory;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyList;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.inOrder;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class McpScanLauncherTest {

    private static final String ENDPOINT = "https://example.com/mcp";
    private static final String SCHEMA_WITH_TWO_STRING_PROPS = """
            {"properties":{"name":{"type":"string"},"label":{"type":"string"}}}""";
    private static final String SCHEMA_WITH_TWO_PROPS = """
            {"properties":{"name":{"type":"string"},"count":{"type":"integer"}}}""";
    private static final String SCHEMA_NO_PROPS = """
            {"type":"object"}""";

    @Mock private Scanner scanner;
    @Mock private Audit audit;
    @Mock private Logging logging;
    @Mock private MontoyaApi api;
    @Mock private SiteMap siteMap;
    @Mock private Http http;

    private final Map<String, String> headers = Map.of();
    private McpScanLauncher launcher;
    private McpEventLog eventLog;

    @BeforeAll
    static void installFactory() {
        MontoyaTestFactory.install();
    }

    private static final String SESSION_ENDPOINT = "https://example.com/mcp";
    private final ScanStartContext sessionContext = new ScanStartContext(SESSION_ENDPOINT, Map.of());

    @BeforeEach
    void setUp() {
        lenient().when(scanner.startAudit(any(AuditConfiguration.class))).thenReturn(audit);
        lenient().when(api.scanner()).thenReturn(scanner);
        lenient().when(api.logging()).thenReturn(logging);
        lenient().when(api.siteMap()).thenReturn(siteMap);
        lenient().when(api.http()).thenReturn(http);
        eventLog = new McpEventLog(null);
        launcher = new McpScanLauncher(api, eventLog, new JsonRpcRequestBuilder(),
                () -> sessionContext, List.of());
    }

    @Test
    void startsAuditWithCorrectConfiguration() {
        launcher.launchScan(ENDPOINT, ScanInventory.toolsOnly(List.of()), headers);

        verify(scanner).startAudit(any(AuditConfiguration.class));
    }

    @Test
    void eachToolGeneratesRequestAddedToAudit() {
        McpToolDefinition tool1 = new McpToolDefinition("toolA", "desc", SCHEMA_WITH_TWO_PROPS);
        McpToolDefinition tool2 = new McpToolDefinition("toolB", "desc", SCHEMA_WITH_TWO_PROPS);

        launcher.launchScan(ENDPOINT, ScanInventory.toolsOnly(List.of(tool1, tool2)), headers);

        verify(audit, times(2)).addRequest(any(HttpRequest.class), anyList());
    }

    @Test
    void correctNumberOfRangesPerTool() {
        McpToolDefinition tool = new McpToolDefinition("toolA", "desc", SCHEMA_WITH_TWO_STRING_PROPS);

        launcher.launchScan(ENDPOINT, ScanInventory.toolsOnly(List.of(tool)), headers);

        @SuppressWarnings("unchecked")
        ArgumentCaptor<List<Range>> rangesCaptor = ArgumentCaptor.forClass(List.class);
        verify(audit).addRequest(any(HttpRequest.class), rangesCaptor.capture());
        assertThat(rangesCaptor.getValue()).hasSize(2);
    }

    @Test
    void logsAddedAndSkippedTools() {
        McpToolDefinition tool1 = new McpToolDefinition("toolA", "desc", SCHEMA_WITH_TWO_STRING_PROPS);
        McpToolDefinition tool2 = new McpToolDefinition("toolB", "desc", SCHEMA_NO_PROPS);

        launcher.launchScan(ENDPOINT, ScanInventory.toolsOnly(List.of(tool1, tool2)), headers);

        verify(logging).logToOutput("Added tool to audit: toolA with 2 insertion points");
        verify(logging).logToOutput("Skipped tool with no fuzzable input: toolB");
    }

    @Test
    void emptyToolListStartsAuditWithNoRequests() {
        Audit result = launcher.launchScan(ENDPOINT, ScanInventory.toolsOnly(List.of()), headers);

        assertThat(result).isSameAs(audit);
        verify(scanner).startAudit(any(AuditConfiguration.class));
        verify(audit, never()).addRequest(any(HttpRequest.class), anyList());
    }

    @Test
    void toolWithNoPropertiesIsNotAddedToAudit() {
        McpToolDefinition tool = new McpToolDefinition("noProps", "desc", SCHEMA_NO_PROPS);

        launcher.launchScan(ENDPOINT, ScanInventory.toolsOnly(List.of(tool)), headers);

        verify(audit, never()).addRequest(any(HttpRequest.class), anyList());
    }

    @Test
    void returnsAuditObject() {
        McpToolDefinition tool = new McpToolDefinition("toolA", "desc", SCHEMA_WITH_TWO_PROPS);

        Audit result = launcher.launchScan(ENDPOINT, ScanInventory.toolsOnly(List.of(tool)), headers);

        assertThat(result).isSameAs(audit);
    }

    @Test
    void eachResourceGeneratesRequestAddedToAudit() {
        McpResourceDefinition r1 = new McpResourceDefinition("file:///a", "a", "desc", "text/plain");
        McpResourceDefinition r2 = new McpResourceDefinition("file:///b", "b", "desc", "text/plain");
        ScanInventory inventory = new ScanInventory(
                List.of(), List.of(r1, r2), List.of(), List.of());

        launcher.launchScan(ENDPOINT, inventory, headers);

        verify(audit, times(2)).addRequest(any(HttpRequest.class), anyList());
    }

    @Test
    void resourceProducesSingleUriInsertionPoint() {
        McpResourceDefinition resource = new McpResourceDefinition(
                "file:///etc/passwd", "passwd", "desc", "text/plain");
        ScanInventory inventory = new ScanInventory(
                List.of(), List.of(resource), List.of(), List.of());

        launcher.launchScan(ENDPOINT, inventory, headers);

        @SuppressWarnings("unchecked")
        ArgumentCaptor<List<Range>> rangesCaptor = ArgumentCaptor.forClass(List.class);
        verify(audit).addRequest(any(HttpRequest.class), rangesCaptor.capture());
        assertThat(rangesCaptor.getValue()).hasSize(1);
    }

    @Test
    void resourceTemplateProducesOnePerPlaceholder() {
        McpResourceTemplateDefinition template = new McpResourceTemplateDefinition(
                "db://{server}/{database}/{table}", "db", "desc", "application/json");
        ScanInventory inventory = new ScanInventory(
                List.of(), List.of(), List.of(template), List.of());

        launcher.launchScan(ENDPOINT, inventory, headers);

        @SuppressWarnings("unchecked")
        ArgumentCaptor<List<Range>> rangesCaptor = ArgumentCaptor.forClass(List.class);
        verify(audit).addRequest(any(HttpRequest.class), rangesCaptor.capture());
        assertThat(rangesCaptor.getValue()).hasSize(3);
    }

    @Test
    void resourceTemplateWithoutPlaceholdersIsSkipped() {
        McpResourceTemplateDefinition template = new McpResourceTemplateDefinition(
                "file:///static", "static", "desc", "text/plain");
        ScanInventory inventory = new ScanInventory(
                List.of(), List.of(), List.of(template), List.of());

        launcher.launchScan(ENDPOINT, inventory, headers);

        verify(audit, never()).addRequest(any(HttpRequest.class), anyList());
        verify(logging).logToOutput("Skipped resource template with no fuzzable input: file:///static");
    }

    @Test
    void promptGeneratesOneInsertionPointPerArgument() {
        McpPromptDefinition prompt = new McpPromptDefinition(
                "summarize", "desc",
                List.of(new PromptArgument("topic", "what to summarize", true),
                        new PromptArgument("style", "tone", false)));
        ScanInventory inventory = new ScanInventory(
                List.of(), List.of(), List.of(), List.of(prompt));

        launcher.launchScan(ENDPOINT, inventory, headers);

        @SuppressWarnings("unchecked")
        ArgumentCaptor<List<Range>> rangesCaptor = ArgumentCaptor.forClass(List.class);
        verify(audit).addRequest(any(HttpRequest.class), rangesCaptor.capture());
        assertThat(rangesCaptor.getValue()).hasSize(2);
    }

    @Test
    void promptWithoutArgumentsIsSkipped() {
        McpPromptDefinition prompt = new McpPromptDefinition("noargs", "desc", List.of());
        ScanInventory inventory = new ScanInventory(
                List.of(), List.of(), List.of(), List.of(prompt));

        launcher.launchScan(ENDPOINT, inventory, headers);

        verify(audit, never()).addRequest(any(HttpRequest.class), anyList());
        verify(logging).logToOutput("Skipped prompt with no fuzzable input: noargs");
    }

    @Test
    void launchScanStartsAuditOnceAndAddsRequestPerScannableItem() {
        McpToolDefinition tool1 = new McpToolDefinition("toolA", "desc", SCHEMA_WITH_TWO_STRING_PROPS);
        McpToolDefinition tool2 = new McpToolDefinition("toolB", "desc", SCHEMA_WITH_TWO_STRING_PROPS);

        launcher.launchScan(ENDPOINT, ScanInventory.toolsOnly(List.of(tool1, tool2)), headers);

        ArgumentCaptor<AuditConfiguration> configCaptor = ArgumentCaptor.forClass(AuditConfiguration.class);
        verify(scanner, times(1)).startAudit(configCaptor.capture());
        verify(audit, times(2)).addRequest(any(HttpRequest.class), anyList());
    }

    @Test
    void launchScanLogsAuditStartedSummaryToEventLog() {
        McpToolDefinition tool1 = new McpToolDefinition("toolA", "desc", SCHEMA_WITH_TWO_STRING_PROPS);
        McpToolDefinition tool2 = new McpToolDefinition("toolB", "desc", SCHEMA_WITH_TWO_STRING_PROPS);

        launcher.launchScan(ENDPOINT, ScanInventory.toolsOnly(List.of(tool1, tool2)), headers);

        assertThat(eventLog.snapshot())
                .anyMatch(entry -> entry.level() == McpEventLog.Level.INFO
                        && entry.message().equals(
                        "Audit started — 2 requests, 4 insertion points"));
    }

    @Test
    void launchScanAuditStartedSummaryPluralisesGracefully() {
        McpToolDefinition tool = new McpToolDefinition("only", "desc", SCHEMA_WITH_TWO_STRING_PROPS);
        // One scannable request with two insertion points
        launcher.launchScan(ENDPOINT, ScanInventory.toolsOnly(List.of(tool)), headers);

        assertThat(eventLog.snapshot())
                .anyMatch(entry -> entry.level() == McpEventLog.Level.INFO
                        && entry.message().equals(
                        "Audit started — 1 request, 2 insertion points"));
    }

    @Test
    void skippedEntrySurfacesAsWarnInEventLog() {
        McpToolDefinition tool = new McpToolDefinition("noProps", "desc", SCHEMA_NO_PROPS);

        launcher.launchScan(ENDPOINT, ScanInventory.toolsOnly(List.of(tool)), headers);

        assertThat(eventLog.snapshot())
                .anyMatch(entry -> entry.level() == McpEventLog.Level.WARN
                        && entry.message().contains("Skipped tool with no fuzzable input: noProps"));
    }

    @Test
    void mixedInventoryQueuesExpectedRequestCount() {
        McpToolDefinition tool = new McpToolDefinition("t", "desc", SCHEMA_WITH_TWO_STRING_PROPS);
        McpResourceDefinition resource = new McpResourceDefinition("file:///x", "x", "desc", "text/plain");
        McpResourceTemplateDefinition template = new McpResourceTemplateDefinition(
                "file:///{p}", "tmpl", "desc", "text/plain");
        McpPromptDefinition prompt = new McpPromptDefinition(
                "p", "desc", List.of(new PromptArgument("topic", null, true)));
        ScanInventory inventory = new ScanInventory(
                List.of(tool), List.of(resource), List.of(template), List.of(prompt));

        launcher.launchScan(ENDPOINT, inventory, headers);

        verify(audit, times(4)).addRequest(any(HttpRequest.class), anyList());
    }

    // ---------- Scan-start check dispatch (Task 6) ----------

    @Test
    void launchScan_invokesEachScanStartCheckWithContextAndApiHttp() {
        AuditIssue issue = stubIssue("OAuth Token");
        ScanStartCheck check = mock(ScanStartCheck.class);
        when(check.runOnceForSession(any(ScanStartContext.class), eq(http))).thenReturn(List.of(issue));
        launcher = new McpScanLauncher(api, eventLog, new JsonRpcRequestBuilder(), () -> sessionContext, List.of(check));

        launcher.launchScan(ENDPOINT, ScanInventory.toolsOnly(List.of()), headers);

        ArgumentCaptor<ScanStartContext> contextCaptor = ArgumentCaptor.forClass(ScanStartContext.class);
        verify(check).runOnceForSession(contextCaptor.capture(), eq(http));
        assertThat(contextCaptor.getValue().endpoint()).isEqualTo(SESSION_ENDPOINT);
    }

    @Test
    void launchScan_publishesScanStartIssuesToSiteMap() {
        AuditIssue issueA = stubIssue("OAuth Token");
        AuditIssue issueB = stubIssue("DCR");
        ScanStartCheck checkA = mock(ScanStartCheck.class);
        ScanStartCheck checkB = mock(ScanStartCheck.class);
        when(checkA.runOnceForSession(any(ScanStartContext.class), eq(http))).thenReturn(List.of(issueA));
        when(checkB.runOnceForSession(any(ScanStartContext.class), eq(http))).thenReturn(List.of(issueB));
        launcher = new McpScanLauncher(api, eventLog, new JsonRpcRequestBuilder(), () -> sessionContext,
                List.of(checkA, checkB));

        launcher.launchScan(ENDPOINT, ScanInventory.toolsOnly(List.of()), headers);

        verify(siteMap).add(issueA);
        verify(siteMap).add(issueB);
    }

    @Test
    void launchScan_runsScanStartChecksBeforeQueueingAudit() {
        McpToolDefinition tool = new McpToolDefinition("toolA", "desc", SCHEMA_WITH_TWO_PROPS);
        AuditIssue issue = stubIssue("OAuth Token");
        ScanStartCheck check = mock(ScanStartCheck.class);
        when(check.runOnceForSession(any(ScanStartContext.class), eq(http))).thenReturn(List.of(issue));
        launcher = new McpScanLauncher(api, eventLog, new JsonRpcRequestBuilder(), () -> sessionContext, List.of(check));

        launcher.launchScan(ENDPOINT, ScanInventory.toolsOnly(List.of(tool)), headers);

        var inOrder = inOrder(check, siteMap, audit);
        inOrder.verify(check).runOnceForSession(any(ScanStartContext.class), eq(http));
        inOrder.verify(siteMap).add(issue);
        inOrder.verify(audit).addRequest(any(HttpRequest.class), anyList());
    }

    @Test
    void launchScan_continuesWhenScanStartCheckEmitsNoIssues() {
        ScanStartCheck check = mock(ScanStartCheck.class);
        when(check.runOnceForSession(any(ScanStartContext.class), eq(http))).thenReturn(List.of());
        launcher = new McpScanLauncher(api, eventLog, new JsonRpcRequestBuilder(), () -> sessionContext, List.of(check));

        launcher.launchScan(ENDPOINT, ScanInventory.toolsOnly(List.of()), headers);

        verify(siteMap, never()).add(any(AuditIssue.class));
        verify(scanner).startAudit(any(AuditConfiguration.class));
    }

    @Test
    void launchScan_isolatesScanStartCheckFailures() {
        ScanStartCheck failing = mock(ScanStartCheck.class);
        when(failing.runOnceForSession(any(ScanStartContext.class), eq(http)))
                .thenThrow(new RuntimeException("boom"));
        ScanStartCheck healthy = mock(ScanStartCheck.class);
        AuditIssue issue = stubIssue("DCR");
        when(healthy.runOnceForSession(any(ScanStartContext.class), eq(http))).thenReturn(List.of(issue));
        launcher = new McpScanLauncher(api, eventLog, new JsonRpcRequestBuilder(), () -> sessionContext,
                List.of(failing, healthy));

        launcher.launchScan(ENDPOINT, ScanInventory.toolsOnly(List.of()), headers);

        verify(healthy).runOnceForSession(any(ScanStartContext.class), eq(http));
        verify(siteMap).add(issue);
        verify(scanner).startAudit(any(AuditConfiguration.class));
    }

    // ---------- Retained-audit cleanup on disconnect (audit medium F) ----------

    @Test
    void clearActiveScansDropsRetainedAuditsWithoutCancelling() {
        launcher.launchScan(ENDPOINT, ScanInventory.toolsOnly(List.of()), headers);
        launcher.launchScan(ENDPOINT, ScanInventory.toolsOnly(List.of()), headers);

        launcher.clearActiveScans();

        verify(audit, never()).delete();
        // References dropped, so a subsequent shutdown cancel has nothing to delete.
        launcher.cancelActiveScans();
        verify(audit, never()).delete();
    }

    @Test
    void cancelActiveScansStillDeletesRetainedAudits() {
        launcher.launchScan(ENDPOINT, ScanInventory.toolsOnly(List.of()), headers);

        launcher.cancelActiveScans();

        verify(audit).delete();
    }

    private static AuditIssue stubIssue(String name) {
        AuditIssue issue = mock(AuditIssue.class);
        lenient().when(issue.name()).thenReturn(name);
        lenient().when(issue.severity()).thenReturn(AuditIssueSeverity.HIGH);
        lenient().when(issue.confidence()).thenReturn(AuditIssueConfidence.FIRM);
        return issue;
    }
}
