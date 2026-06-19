package com.mcpscanner.checks.content;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.HttpService;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.api.montoya.scanner.AuditResult;
import burp.api.montoya.scanner.audit.issues.AuditIssue;
import burp.api.montoya.sitemap.SiteMap;
import com.mcpscanner.checks.JsonRpcDiscoveryResponseScanner;
import com.mcpscanner.checks.content.rules.AwsAccessKeyRule;
import com.mcpscanner.checks.registry.ScanCheckSettings;
import com.mcpscanner.mcp.McpToolDefinition;
import com.mcpscanner.mcp.ServerMetadata;
import com.mcpscanner.testutil.MontoyaTestFactory;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;

import java.util.ArrayList;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.anyBoolean;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.atLeast;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * Regression for the connect-time double-report: the on-connect {@link DiscoveryContentScanner}
 * (emits via {@code siteMap().add(...)}) and the passive {@link JsonRpcDiscoveryResponseScanner}
 * (fed the same discovery responses at connect time) both run the same rules over the same
 * metadata. With a shared {@link ContentFindingDedup} the same secret must emit exactly ONE
 * issue total, whichever surface runs first.
 */
class ContentFindingDoubleReportTest {

    private static final String AWS_KEY = "AKIAQ7777PYTYINTERNAL";

    private MontoyaApi api;
    private SiteMap siteMap;
    private ScanCheckSettings settings;
    private HttpService host;

    @BeforeEach
    void setUp() {
        MontoyaTestFactory.install();
        api = mock(MontoyaApi.class);
        siteMap = mock(SiteMap.class);
        when(api.siteMap()).thenReturn(siteMap);
        settings = mock(ScanCheckSettings.class);
        lenient().when(settings.isEnabled(anyString(), anyBoolean())).thenReturn(true);
        host = mock(HttpService.class);
        lenient().when(host.host()).thenReturn("mcp.example.test");
        lenient().when(host.port()).thenReturn(443);
        lenient().when(host.secure()).thenReturn(true);
    }

    @Test
    void connectTimeScannerWinsAndPassiveScannerSkipsTheDuplicate() {
        ContentFindingDedup dedup = new ContentFindingDedup();
        List<ContentRule> rules = List.of(new AwsAccessKeyRule());

        DiscoveryContentScanner connectScanner = new DiscoveryContentScanner(rules, settings, api, dedup);
        JsonRpcDiscoveryResponseScanner passiveScanner =
                new JsonRpcDiscoveryResponseScanner(settings, rules, dedup);

        connectScanner.scan(awsLeakContent(), host, null);
        List<AuditIssue> passiveIssues = passiveScanner.doCheck(awsLeakResponse()).auditIssues();

        assertThat(connectIssues()).hasSize(1);
        assertThat(passiveIssues).isEmpty();
    }

    @Test
    void passiveScannerWinsAndConnectTimeScannerSkipsTheDuplicate() {
        ContentFindingDedup dedup = new ContentFindingDedup();
        List<ContentRule> rules = List.of(new AwsAccessKeyRule());

        DiscoveryContentScanner connectScanner = new DiscoveryContentScanner(rules, settings, api, dedup);
        JsonRpcDiscoveryResponseScanner passiveScanner =
                new JsonRpcDiscoveryResponseScanner(settings, rules, dedup);

        List<AuditIssue> passiveIssues = passiveScanner.doCheck(awsLeakResponse()).auditIssues();
        connectScanner.scan(awsLeakContent(), host, null);

        assertThat(passiveIssues).hasSize(1);
        verify(siteMap, never()).add(org.mockito.ArgumentMatchers.any(AuditIssue.class));
    }

    @Test
    void uniqueFindingSeenByOnlyOneScannerStillEmits() {
        ContentFindingDedup dedup = new ContentFindingDedup();
        List<ContentRule> rules = List.of(new AwsAccessKeyRule());
        DiscoveryContentScanner connectScanner = new DiscoveryContentScanner(rules, settings, api, dedup);

        // A second distinct secret only the connect-time structured walk sees.
        McpToolDefinition tool = new McpToolDefinition(
                "deploy", "Use " + AWS_KEY + " here", null);
        McpToolDefinition uniqueTool = new McpToolDefinition(
                "release", "And ASIA234567ABCDEFGHIJ there", null);
        DiscoveredContent content = new DiscoveredContent(
                ServerMetadata.empty(), List.of(tool, uniqueTool), List.of(), List.of(), List.of());

        connectScanner.scan(content, host, null);
        JsonRpcDiscoveryResponseScanner passiveScanner =
                new JsonRpcDiscoveryResponseScanner(settings, rules, dedup);
        List<AuditIssue> passiveIssues = passiveScanner.doCheck(awsLeakResponse()).auditIssues();

        // Connect-time emits one AWS issue (grouping both keys into one rule issue);
        // passive sees only the already-claimed AWS_KEY, so it skips entirely.
        assertThat(connectIssues()).hasSize(1);
        assertThat(passiveIssues).isEmpty();
    }

    @Test
    void repeatedSecretWithinOneSurfaceCollapsesToOneFinding() {
        ContentFindingDedup dedup = new ContentFindingDedup();
        List<ContentRule> rules = List.of(new AwsAccessKeyRule());
        DiscoveryContentScanner connectScanner = new DiscoveryContentScanner(rules, settings, api, dedup);

        McpToolDefinition toolA = new McpToolDefinition("a", "Key " + AWS_KEY, null);
        McpToolDefinition toolB = new McpToolDefinition("b", "Same key " + AWS_KEY, null);
        DiscoveredContent content = new DiscoveredContent(
                ServerMetadata.empty(), List.of(toolA, toolB), List.of(), List.of(), List.of());

        connectScanner.scan(content, host, null);

        AuditIssue issue = connectIssues().get(0);
        assertThat(issue.detail())
                .contains("Found 1 AWS Access Keys finding");
    }

    private DiscoveredContent awsLeakContent() {
        McpToolDefinition tool = new McpToolDefinition(
                "leak", "Use " + AWS_KEY + " to authenticate", null);
        return new DiscoveredContent(
                ServerMetadata.empty(), List.of(tool), List.of(), List.of(), List.of());
    }

    private HttpRequestResponse awsLeakResponse() {
        String requestBody = "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/list\"}";
        String responseBody = "{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{\"tools\":[{"
                + "\"name\":\"leak\","
                + "\"description\":\"Use " + AWS_KEY + " to authenticate\""
                + "}]}}";
        HttpRequestResponse rr = mock(HttpRequestResponse.class);
        HttpRequest req = mock(HttpRequest.class);
        HttpResponse resp = mock(HttpResponse.class);
        lenient().when(rr.request()).thenReturn(req);
        lenient().when(rr.response()).thenReturn(resp);
        lenient().when(req.httpService()).thenReturn(host);
        lenient().when(req.method()).thenReturn("POST");
        lenient().when(req.bodyToString()).thenReturn(requestBody);
        lenient().when(req.headerValue("Content-Type")).thenReturn("application/json");
        lenient().when(resp.statusCode()).thenReturn((short) 200);
        lenient().when(resp.bodyToString()).thenReturn(responseBody);
        return rr;
    }

    private List<AuditIssue> connectIssues() {
        ArgumentCaptor<AuditIssue> captor = ArgumentCaptor.forClass(AuditIssue.class);
        verify(siteMap, atLeast(0)).add(captor.capture());
        return new ArrayList<>(captor.getAllValues());
    }
}
