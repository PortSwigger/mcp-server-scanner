package com.mcpscanner.checks.content;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.HttpService;
import burp.api.montoya.scanner.audit.issues.AuditIssue;
import burp.api.montoya.sitemap.SiteMap;
import com.mcpscanner.checks.registry.ScanCheckSettings;
import com.mcpscanner.mcp.IconDescriptor;
import com.mcpscanner.mcp.McpPromptDefinition;
import com.mcpscanner.mcp.McpResourceDefinition;
import com.mcpscanner.mcp.McpToolDefinition;
import com.mcpscanner.mcp.PromptArgument;
import com.mcpscanner.mcp.ServerMetadata;
import com.mcpscanner.testutil.MontoyaTestFactory;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;

import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.atLeastOnce;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * Golden snapshot for the connect-time DiscoveryContentScanner emission path.
 * Locks in byte-identical behaviour across T7's refactor: same set of issues,
 * same names, same severity, same confidence, same detail content per rule.
 */
class DiscoveryContentScannerGoldenSnapshotTest {

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
        lenient().when(settings.isEnabled(any(String.class), any(Boolean.class))).thenReturn(true);
        host = mock(HttpService.class);
        lenient().when(host.host()).thenReturn("mcp.example.test");
        lenient().when(host.port()).thenReturn(443);
        lenient().when(host.secure()).thenReturn(true);
    }

    @Test
    void richFixtureProducesByteIdenticalIssueSet() {
        DiscoveryContentScanner scanner =
                new DiscoveryContentScanner(ContentRules.all(), settings, api);

        scanner.scan(richFixture(), host, null);

        List<String> actual = capturedIssues().stream()
                .map(DiscoveryContentScannerGoldenSnapshotTest::serialize)
                .sorted()
                .toList();
        assertThat(actual).containsExactlyElementsOf(EXPECTED_SNAPSHOT);
    }

    /**
     * Baked-in expected snapshot. Each line is name|severity|confidence|baseUrl|detailDigest
     * where detailDigest is a stable subset of the detail (sorted hits with field path + matched text)
     * to avoid coupling to internal ordering quirks while still locking in observable behaviour.
     */
    private static final List<String> EXPECTED_SNAPSHOT = List.of(
            "AWS Access Keys in MCP discovery|HIGH|FIRM|null"
                    + "|TOOL &quot;send_email&quot;.description -&gt; AKIA234567ABCDEFGHIJ",
            "Email Addresses in MCP discovery|INFORMATION|TENTATIVE|null"
                    + "|TOOL &quot;send_email&quot;.description -&gt; alice@acme.io",
            "JWT Tokens in MCP discovery|INFORMATION|TENTATIVE|null"
                    + "|SERVER_INFO &quot;(initialize)&quot;.instructions -&gt; "
                    + "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ1c2VyMSJ9.signaturePartIsLong",
            "Private/Loopback URLs in MCP discovery|INFORMATION|TENTATIVE|null"
                    + "|RESOURCE &quot;internal_dashboard&quot;.description -&gt; http://10.0.0.5/admin",
            "Unsafe Icon URIs in MCP discovery|HIGH|FIRM|null"
                    + "|TOOL &quot;send_email&quot;.icons[0].src (unsafe scheme) -&gt; file:///etc/passwd"
    );

    private DiscoveredContent richFixture() {
        ServerMetadata server = new ServerMetadata(
                Map.of("name", "demo", "version", "1.0"),
                "Auth via eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ1c2VyMSJ9.signaturePartIsLong",
                Map.of());
        McpToolDefinition tool = new McpToolDefinition(
                "send_email",
                "Contact alice@acme.io with key AKIA234567ABCDEFGHIJ",
                null,
                List.of(new IconDescriptor("file:///etc/passwd", "image/png", List.of())));
        McpResourceDefinition resource = new McpResourceDefinition(
                "https://docs.example.test/dash",
                "internal_dashboard",
                "Reachable at http://10.0.0.5/admin",
                null);
        McpPromptDefinition prompt = new McpPromptDefinition(
                "rotate", "Standard prompt",
                List.of(new PromptArgument("region", "AWS region", true)));
        return new DiscoveredContent(server, List.of(tool), List.of(resource), List.of(), List.of(prompt));
    }

    private List<AuditIssue> capturedIssues() {
        ArgumentCaptor<AuditIssue> captor = ArgumentCaptor.forClass(AuditIssue.class);
        verify(siteMap, atLeastOnce()).add(captor.capture());
        return captor.getAllValues();
    }

    private static String serialize(AuditIssue issue) {
        return issue.name()
                + "|" + issue.severity()
                + "|" + issue.confidence()
                + "|" + issue.baseUrl()
                + "|" + detailDigest(issue.detail());
    }

    private static String detailDigest(String detail) {
        if (detail == null) {
            return "";
        }
        int ulStart = detail.indexOf("<ul>");
        int ulEnd = detail.indexOf("</ul>", ulStart);
        if (ulStart < 0 || ulEnd < 0) {
            return "";
        }
        String findingsList = detail.substring(ulStart + "<ul>".length(), ulEnd);
        List<String> items = new java.util.ArrayList<>();
        int cursor = 0;
        while (true) {
            int liStart = findingsList.indexOf("<li>", cursor);
            if (liStart < 0) {
                break;
            }
            int liEnd = findingsList.indexOf("</li>", liStart);
            if (liEnd < 0) {
                break;
            }
            items.add(findingsList.substring(liStart + "<li>".length(), liEnd));
            cursor = liEnd + "</li>".length();
        }
        return String.join(" | ", items);
    }
}
