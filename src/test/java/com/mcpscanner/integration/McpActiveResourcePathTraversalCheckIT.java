package com.mcpscanner.integration;

import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.scanner.AuditResult;
import burp.api.montoya.scanner.audit.insertionpoint.AuditInsertionPoint;
import burp.api.montoya.scanner.audit.issues.AuditIssue;
import burp.api.montoya.scanner.audit.issues.AuditIssueConfidence;
import burp.api.montoya.scanner.audit.issues.AuditIssueSeverity;
import com.mcpscanner.checks.McpActiveResourcePathTraversalCheck;
import com.mcpscanner.checks.registry.ScanCheckSettings;
import com.mcpscanner.testutil.MontoyaTestFactory;
import com.mcpscanner.testutil.RecordingRealHttp;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledIfEnvironmentVariable;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.api.io.TempDir;
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
 * Live end-to-end matrix for {@link McpActiveResourcePathTraversalCheck} against the deliberately
 * broken Python resource fixtures (one per real CVE shape) plus the safe negative control.
 *
 * <p>Each case starts the test-server with ONLY its target resource fixture enabled
 * ({@code --enable <name>}) so the tier under test is isolated and the per-issue assertions cannot
 * be confused by another fixture's behaviour.
 *
 * <p><b>Documented harness boundary.</b> FastMCP resource templates ({@code scheme:///{path}})
 * match a single template variable and drop URIs containing a literal {@code /}. A literal
 * {@code ../} therefore never reaches the resource handler — it is rejected at the routing layer
 * with "Unknown resource". As a result the <em>plain-vs-encoded differential cannot be observed</em>
 * against FastMCP-based servers: the {@code rooted} (no sanitizer) and {@code encoded}
 * (decode-after-check) fixtures are remotely indistinguishable and both correctly fire as
 * {@code TRAVERSAL} (an out-of-root file was disclosed). The {@code ENCODING_BYPASS} tier — which
 * requires positive evidence the literal {@code ../} was delivered to the handler and rejected
 * there — is exercised by the unit suite (and applies to real slash-routing servers) but is not
 * reproducible here. This is asserted, not hidden, so the check never over-claims a broken
 * sanitizer it could not actually prove.
 */
@EnabledIfEnvironmentVariable(named = "MCP_E2E_IT", matches = "1")
@ExtendWith(MockitoExtension.class)
class McpActiveResourcePathTraversalCheckIT {

    private static final String TRAVERSAL = "MCP Resource Path Traversal";
    private static final String ENCODING_BYPASS = "MCP Resource Path Traversal (Encoding Bypass)";
    private static final String PREFIX_SIBLING = "MCP Resource Path Traversal (Root Boundary Bypass)";
    private static final String ABSOLUTE = "MCP Resource Arbitrary File Read";

    @BeforeAll
    static void installFactory() {
        MontoyaTestFactory.install();
    }

    @Mock
    private ScanCheckSettings settings;

    @Mock
    private AuditInsertionPoint insertionPoint;

    @Test
    void rootedFixtureFiresTraversalHighFirm() throws Exception {
        Path root = seededRoot();
        try (McpCheckItSupport.RunningServer server = startWith(root, "read_file_rooted")) {
            AuditResult result = runCheck(server);

            AuditIssue issue = issueNamed(result, TRAVERSAL);
            assertThat(issue.severity()).isEqualTo(AuditIssueSeverity.HIGH);
            assertThat(issue.confidence()).isEqualTo(AuditIssueConfidence.FIRM);
        }
    }

    @Test
    void encodedFixtureFiresTraversalAndDoesNotOverClaimEncodingBypass() throws Exception {
        // The literal ../ probe never reaches the handler (FastMCP routing drops literal-slash
        // URIs), so the encoding-bypass differential cannot be observed — the encoded escape that
        // discloses the file is an ordinary traversal, NOT proof of a broken sanitizer. The check
        // must report TRAVERSAL and must NOT over-claim ENCODING_BYPASS.
        Path root = seededRoot();
        try (McpCheckItSupport.RunningServer server = startWith(root, "read_file_encoded")) {
            AuditResult result = runCheck(server);

            assertThat(result.auditIssues()).extracting(AuditIssue::name)
                    .contains(TRAVERSAL)
                    .doesNotContain(ENCODING_BYPASS);
            AuditIssue issue = issueNamed(result, TRAVERSAL);
            assertThat(issue.severity()).isEqualTo(AuditIssueSeverity.HIGH);
            assertThat(issue.confidence()).isEqualTo(AuditIssueConfidence.FIRM);
        }
    }

    @Test
    void prefixMatchFixtureFiresRootBoundaryBypassMediumFirm() throws Exception {
        Path root = seededRoot();
        try (McpCheckItSupport.RunningServer server = startWith(root, "read_file_prefixmatch")) {
            AuditResult result = runCheck(server);

            AuditIssue issue = issueNamed(result, PREFIX_SIBLING);
            assertThat(issue.severity()).isEqualTo(AuditIssueSeverity.MEDIUM);
            assertThat(issue.confidence()).isEqualTo(AuditIssueConfidence.FIRM);
        }
    }

    @Test
    void safeFixtureFiresNoTraversalIssue() throws Exception {
        Path root = seededRoot();
        try (McpCheckItSupport.RunningServer server = startWith(root, "read_file_safe")) {
            AuditResult result = runCheck(server);

            assertThat(result.auditIssues())
                    .as("correctly sandboxed reader must produce no path-traversal finding")
                    .isEmpty();
        }
    }

    @Test
    void symlinkFixtureFiresNoIssueDocumentedRemoteBoundary() throws Exception {
        // CVE-2025-53109/67364: the only escape is via an on-disk symlink the scanner cannot plant
        // over JSON-RPC. Every URI the check can send is rejected, proving the check does not
        // over-claim a vulnerability it cannot remotely demonstrate.
        Path root = seededRoot();
        try (McpCheckItSupport.RunningServer server = startWith(root, "read_file_symlink")) {
            AuditResult result = runCheck(server);

            assertThat(result.auditIssues()).isEmpty();
        }
    }

    @Test
    void legacyUnrootedReadFileFiresHedgedAbsoluteMediumTentative() throws Exception {
        // The legacy file:///{path} reader has NO sandbox root, so it serves bare absolute files
        // (the hedged ABSOLUTE/TENTATIVE finding) AND — because its single template variable
        // accepts an encoded escape — discloses files via traversal too. We assert the hedged
        // absolute issue is present and correctly demoted; the co-occurring TRAVERSAL is honest
        // (a rootless reader genuinely permits both) so it is not asserted absent.
        Path root = seededRoot();
        try (McpCheckItSupport.RunningServer server = startWith(root, "read_file")) {
            AuditResult result = runCheck(server);

            AuditIssue issue = issueNamed(result, ABSOLUTE);
            assertThat(issue.severity()).isEqualTo(AuditIssueSeverity.MEDIUM);
            assertThat(issue.confidence()).isEqualTo(AuditIssueConfidence.TENTATIVE);
            assertThat(issue.detail()).contains("working-as-designed");
        }
    }

    private AuditResult runCheck(McpCheckItSupport.RunningServer server) throws Exception {
        when(settings.isEnabled(anyString(), anyBoolean())).thenReturn(true);
        McpActiveResourcePathTraversalCheck check =
                new McpActiveResourcePathTraversalCheck(settings);
        String sessionId = McpCheckItSupport.initializeSession(server.port());
        HttpRequestResponse baseline = resourcesBaseline(server.port(), sessionId);
        RecordingRealHttp http =
                new RecordingRealHttp(McpCheckItSupport.realHttpClient(), sessionId);
        return check.doCheck(baseline, insertionPoint, http);
    }

    private static McpCheckItSupport.RunningServer startWith(Path root, String resourceName)
            throws IOException, InterruptedException {
        return McpCheckItSupport.startServer(
                Map.of("MCP_LAB_RESOURCE_ROOT", root.toString()),
                "--auth", "none", "--enable", resourceName);
    }

    /**
     * Lays out a sandbox root a few directories deep under a temp base, with an in-root canary. The
     * check now sends ONE canonical deep escape ({@code ../}×{@code TraversalEscapes.DEEP_LEVELS});
     * by the clamp principle that over-walks the temp base and resolves at the real filesystem root
     * to the host's {@code /etc/passwd} — present and passwd-shaped on every Linux/macOS CI host —
     * so we no longer seed a depth-pinned {@code <base>/etc/passwd}. A shallower seeded copy would
     * only be reachable by the overfit depth-3 escape this change removed. The CVE-2025-53110
     * prefix-sibling tier uses the no-planted-secret error-differential oracle (a non-existent
     * prefix-sharing sibling returns filesystem not-found while a non-prefix control is denied), so
     * no {@code <root>_mcpscan/passwd} file is seeded either.
     */
    private static Path seededRoot() throws IOException {
        Path base = Files.createTempDirectory("mcp-rpt-it");
        Path root = base.resolve("a").resolve("b").resolve("mcp-lab-res");
        Files.createDirectories(root);
        Files.writeString(root.resolve("notes.txt"), "INSIDE-ROOT-OK");
        Files.writeString(root.resolve("canary.txt"), "canary");
        return root;
    }

    private static HttpRequestResponse resourcesBaseline(int port, String sessionId) {
        HttpRequest request = HttpRequest.httpRequestFromUrl(McpCheckItSupport.mcpEndpoint(port))
                .withMethod("POST")
                .withBody("{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"resources/read\","
                        + "\"params\":{\"uri\":\"file:///etc/hosts\"}}");
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
