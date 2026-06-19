package com.mcpscanner.integration;

import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.scanner.AuditResult;
import burp.api.montoya.scanner.audit.insertionpoint.AuditInsertionPoint;
import burp.api.montoya.scanner.audit.issues.AuditIssue;
import burp.api.montoya.scanner.audit.issues.AuditIssueConfidence;
import burp.api.montoya.scanner.audit.issues.AuditIssueSeverity;
import com.mcpscanner.checks.McpActiveToolArgumentPathTraversalCheck;
import com.mcpscanner.checks.registry.ScanCheckSettings;
import com.mcpscanner.mcp.McpToolDefinition;
import com.mcpscanner.scan.ScanInventory;
import com.mcpscanner.testutil.MontoyaTestFactory;
import com.mcpscanner.testutil.RecordingRealHttp;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledIfEnvironmentVariable;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.anyBoolean;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.when;

/**
 * Live end-to-end matrix for {@link McpActiveToolArgumentPathTraversalCheck} against the
 * deliberately broken Python TOOL fixtures (one per real CVE shape) plus the safe negative control.
 *
 * <p>Each case starts the test-server with ONLY its target tool fixture enabled
 * ({@code --enable <name>}) so the tier under test is isolated. Unlike resource templates, a tool
 * argument is a plain JSON string, so a literal {@code ../} DOES reach the handler — which makes the
 * plain-vs-encoded ENCODING_BYPASS differential fully observable here (the decode-after-check
 * fixture fires ENCODING_BYPASS, not a hedged TRAVERSAL).
 */
@EnabledIfEnvironmentVariable(named = "MCP_E2E_IT", matches = "1")
@ExtendWith(MockitoExtension.class)
class McpActiveToolArgumentPathTraversalCheckIT {

    private static final String TRAVERSAL = "MCP Tool Argument Path Traversal";
    private static final String ENCODING_BYPASS = "MCP Tool Argument Path Traversal (Encoding Bypass)";
    private static final String PREFIX_SIBLING = "MCP Tool Argument Path Traversal (Root Boundary Bypass)";
    private static final String ABSOLUTE = "MCP Tool Argument Arbitrary File Read";

    private static final String PATH_SCHEMA =
            "{\"type\":\"object\","
                    + "\"properties\":{\"path\":{\"type\":\"string\",\"description\":\"Filesystem path to read.\"}},"
                    + "\"required\":[\"path\"]}";

    @BeforeAll
    static void installFactory() {
        MontoyaTestFactory.install();
    }

    @Mock
    private ScanCheckSettings settings;

    @Mock
    private AuditInsertionPoint insertionPoint;

    @Test
    void unrootedReadFileToolFiresTraversalHighFirm() throws Exception {
        Path root = seededRoot("MCP_LAB_WORKSPACE_ROOT");
        try (McpCheckItSupport.RunningServer server = startWith(root, "MCP_LAB_WORKSPACE_ROOT",
                "read_file_tool")) {
            AuditResult result = runCheck(server, tool("read_file_tool"));

            AuditIssue issue = issueNamed(result, TRAVERSAL);
            assertThat(issue.severity()).isEqualTo(AuditIssueSeverity.HIGH);
            assertThat(issue.confidence()).isEqualTo(AuditIssueConfidence.FIRM);
        }
    }

    @Test
    void encodedToolFiresEncodingBypassHighCertain() throws Exception {
        // The literal ../ reaches the handler (plain JSON string) and is rejected there; the
        // percent-encoded twin sails past the decode-after-check filter and discloses the file.
        Path root = seededRoot("MCP_LAB_ENCODED_ROOT");
        try (McpCheckItSupport.RunningServer server = startWith(root, "MCP_LAB_ENCODED_ROOT",
                "read_file_encoded_tool")) {
            AuditResult result = runCheck(server, tool("read_file_encoded_tool"));

            AuditIssue issue = issueNamed(result, ENCODING_BYPASS);
            assertThat(issue.severity()).isEqualTo(AuditIssueSeverity.HIGH);
            assertThat(issue.confidence()).isEqualTo(AuditIssueConfidence.CERTAIN);
        }
    }

    @Test
    void prefixMatchToolFiresRootBoundaryBypassMediumFirm() throws Exception {
        // Root derived from the list_allowed_directories tool (enabled alongside); a non-existent
        // out-of-root sibling sharing the prefix returns a filesystem not-found (CVE-2025-53110).
        Path root = seededRoot("MCP_LAB_PREFIXMATCH_ROOT");
        try (McpCheckItSupport.RunningServer server = startWith(root, "MCP_LAB_PREFIXMATCH_ROOT",
                "read_file_prefixmatch_tool", "list_allowed_directories")) {
            AuditResult result = runCheck(server, tool("read_file_prefixmatch_tool"));

            AuditIssue issue = issueNamed(result, PREFIX_SIBLING);
            assertThat(issue.severity()).isEqualTo(AuditIssueSeverity.MEDIUM);
            assertThat(issue.confidence()).isEqualTo(AuditIssueConfidence.FIRM);
            assertThat(issue.detail()).contains("CVE-2025-53110");
        }
    }

    @Test
    void safeToolFiresNoIssue() throws Exception {
        Path root = seededRoot("MCP_LAB_SAFE_ROOT");
        try (McpCheckItSupport.RunningServer server = startWith(root, "MCP_LAB_SAFE_ROOT",
                "read_file_safe_tool", "list_allowed_directories")) {
            AuditResult result = runCheck(server, tool("read_file_safe_tool"));

            assertThat(result.auditIssues())
                    .as("correctly sandboxed tool must produce no path-traversal finding")
                    .isEmpty();
        }
    }

    private AuditResult runCheck(McpCheckItSupport.RunningServer server, McpToolDefinition selected)
            throws Exception {
        when(settings.isEnabled(anyString(), anyBoolean())).thenReturn(true);
        ScanInventory inventory = ScanInventory.toolsOnly(List.of(selected));
        McpActiveToolArgumentPathTraversalCheck check =
                new McpActiveToolArgumentPathTraversalCheck(settings, null, () -> inventory);
        String sessionId = McpCheckItSupport.initializeSession(server.port());
        HttpRequestResponse baseline = toolsCallBaseline(server.port(), sessionId, selected.name());
        RecordingRealHttp http =
                new RecordingRealHttp(McpCheckItSupport.realHttpClient(), sessionId);
        return check.doCheck(baseline, insertionPoint, http);
    }

    private static McpToolDefinition tool(String name) {
        return new McpToolDefinition(name, "Read a file from a path argument.", PATH_SCHEMA);
    }

    private static McpCheckItSupport.RunningServer startWith(Path root, String rootEnv,
                                                             String... enabledTools)
            throws IOException, InterruptedException {
        String[] args = new String[2 + enabledTools.length * 2];
        args[0] = "--auth";
        args[1] = "none";
        for (int i = 0; i < enabledTools.length; i++) {
            args[2 + i * 2] = "--enable";
            args[3 + i * 2] = enabledTools[i];
        }
        return McpCheckItSupport.startServer(Map.of(rootEnv, root.toString()), args);
    }

    /**
     * Lays out a sandbox root a few directories deep under a temp base, with an in-root benign file.
     * The TRAVERSAL/ENCODING_BYPASS tiers now send ONE canonical deep escape
     * ({@code ../}×{@code TraversalEscapes.DEEP_LEVELS}); by the clamp principle that over-walks the
     * temp base and resolves at the real filesystem root to the host's {@code /etc/passwd} (present
     * and passwd-shaped on every Linux/macOS CI host), so we no longer seed a depth-pinned
     * {@code <base>/etc/passwd} — a shallower seeded copy would only be reachable by the overfit
     * depth-3 escape this change removed. The CVE-2025-53110 prefix-sibling tier is the
     * not-found-vs-denied error differential over a non-existent prefix-sharing sibling, so it needs
     * no planted secret either.
     */
    private static Path seededRoot(String rootEnv) throws IOException {
        Path base = Files.createTempDirectory("mcp-tool-rpt-it");
        Path root = base.resolve("a").resolve("b").resolve(rootEnv.toLowerCase());
        Files.createDirectories(root);
        Files.writeString(root.resolve("notes.txt"), "INSIDE-ROOT-OK");
        return root;
    }

    private static HttpRequestResponse toolsCallBaseline(int port, String sessionId, String toolName) {
        HttpRequest request = HttpRequest.httpRequestFromUrl(McpCheckItSupport.mcpEndpoint(port))
                .withMethod("POST")
                .withBody("{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/call\","
                        + "\"params\":{\"name\":\"" + toolName + "\",\"arguments\":{\"path\":\"notes.txt\"}}}");
        if (sessionId != null) {
            request = request.withAddedHeader("Mcp-Session-Id", sessionId);
        }
        return HttpRequestResponse.httpRequestResponse(request, null);
    }

    private static AuditIssue issueNamed(AuditResult result, String name) {
        List<AuditIssue> matches = result.auditIssues().stream()
                .filter(issue -> issue.name().equals(name))
                .toList();
        assertThat(matches)
                .as("expected exactly one '%s' issue; all issues = %s", name,
                        result.auditIssues().stream().map(AuditIssue::name).toList())
                .hasSize(1);
        return matches.get(0);
    }
}
