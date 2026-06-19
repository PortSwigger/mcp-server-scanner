package com.mcpscanner.checks;

import burp.api.montoya.http.Http;
import burp.api.montoya.http.HttpService;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.api.montoya.scanner.AuditResult;
import burp.api.montoya.scanner.audit.insertionpoint.AuditInsertionPoint;
import burp.api.montoya.scanner.audit.issues.AuditIssue;
import burp.api.montoya.scanner.audit.issues.AuditIssueConfidence;
import burp.api.montoya.scanner.audit.issues.AuditIssueSeverity;
import burp.api.montoya.scanner.scancheck.ScanCheckType;
import com.mcpscanner.checks.registry.CheckDescriptor;
import com.mcpscanner.checks.registry.ScanCheckSettings;
import com.mcpscanner.logging.McpEventLog;
import com.mcpscanner.mcp.McpToolDefinition;
import com.mcpscanner.scan.CurrentSelectionHolder;
import com.mcpscanner.scan.ScanInventory;
import com.mcpscanner.testutil.MontoyaTestFactory;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.util.List;
import java.util.function.Function;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyBoolean;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.argThat;
import static org.mockito.ArgumentMatchers.contains;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.spy;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class McpActiveToolArgumentPathTraversalCheckTest {

    private static final String MCP_REQUEST_BODY = "{\"jsonrpc\":\"2.0\",\"method\":\"tools/call\"}";

    private static final String PASSWD_FILE_CONTENT =
            "root:x:0:0:root:/root:/bin/bash\n"
                    + "daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n"
                    + "bin:x:2:2:bin:/bin:/usr/sbin/nologin\n";
    private static final String HOSTS_FILE_CONTENT =
            "127.0.0.1 localhost\n::1 localhost\n";
    private static final String WIN_INI_FILE_CONTENT =
            "; for 16-bit app support\n[fonts]\nMS Sans Serif=ssserife.fon\n";

    private static final String INVALID_PATH_ERROR_BODY =
            "{\"jsonrpc\":\"2.0\",\"result\":{\"content\":[{\"type\":\"text\",\"text\":\"invalid path\"}],\"isError\":true}}";

    private static final String TOOLS_LIST_WITH_PATH_ARG =
            "{\"jsonrpc\":\"2.0\",\"result\":{\"tools\":[{\"name\":\"read_file_tool\",\"description\":\"Read a file\","
                    + "\"inputSchema\":{\"type\":\"object\",\"properties\":"
                    + "{\"path\":{\"type\":\"string\",\"description\":\"Filesystem path to read.\"}},"
                    + "\"required\":[\"path\"]}}]}}";

    // `seed` is NOT in PathArgumentHeuristic.NAME_HINTS, so a
    // hit on this tool can only fire via the DESCRIPTION_HINTS path ("path",
    // "read" — both present in the description below). If we used a name like
    // "target" that's already a name-hint, the test would pass for the wrong
    // reason and never exercise the description-hint branch.
    private static final String TOOLS_LIST_WITH_DESCRIPTION_HINT =
            "{\"jsonrpc\":\"2.0\",\"result\":{\"tools\":[{\"name\":\"open_report\",\"description\":\"Open a report\","
                    + "\"inputSchema\":{\"type\":\"object\",\"properties\":"
                    + "{\"seed\":{\"type\":\"string\",\"description\":\"Filesystem path to read.\"}}}}]}}";

    private static final String TOOLS_LIST_WITHOUT_PATH_ARG =
            "{\"jsonrpc\":\"2.0\",\"result\":{\"tools\":[{\"name\":\"query_user\",\"description\":\"Look up user\","
                    + "\"inputSchema\":{\"type\":\"object\",\"properties\":"
                    + "{\"username\":{\"type\":\"string\",\"description\":\"User to find.\"}}}}]}}";

    private static final String TOOLS_LIST_WITH_LIST_ALLOWED_DIRS =
            "{\"jsonrpc\":\"2.0\",\"result\":{\"tools\":["
                    + "{\"name\":\"read_file_tool\",\"description\":\"Read a file\","
                    + "\"inputSchema\":{\"type\":\"object\",\"properties\":"
                    + "{\"path\":{\"type\":\"string\",\"description\":\"Filesystem path to read.\"}},"
                    + "\"required\":[\"path\"]}},"
                    + "{\"name\":\"list_allowed_directories\",\"description\":\"List roots\","
                    + "\"inputSchema\":{\"type\":\"object\",\"properties\":{}}}"
                    + "]}}";

    private static final String TOOLS_LIST_EMPTY =
            "{\"jsonrpc\":\"2.0\",\"result\":{\"tools\":[]}}";

    private static final String TOOLS_LIST_TWO_PATH_TOOLS =
            "{\"jsonrpc\":\"2.0\",\"result\":{\"tools\":["
                    + "{\"name\":\"read_file_tool\",\"description\":\"Read a file\","
                    + "\"inputSchema\":{\"type\":\"object\",\"properties\":"
                    + "{\"path\":{\"type\":\"string\",\"description\":\"Filesystem path.\"}}}},"
                    + "{\"name\":\"load_doc\",\"description\":\"Load a doc\","
                    + "\"inputSchema\":{\"type\":\"object\",\"properties\":"
                    + "{\"filename\":{\"type\":\"string\",\"description\":\"File to load.\"}}}}"
                    + "]}}";

    private static final String TOOLS_LIST_NULLABLE_PATH_ARG =
            "{\"jsonrpc\":\"2.0\",\"result\":{\"tools\":[{\"name\":\"read_file_tool\","
                    + "\"description\":\"Read a file\","
                    + "\"inputSchema\":{\"type\":\"object\",\"properties\":"
                    + "{\"path\":{\"type\":[\"string\",\"null\"],"
                    + "\"description\":\"Filesystem path to read.\"}},"
                    + "\"required\":[\"path\"]}}]}}";

    @BeforeAll
    static void installFactory() {
        MontoyaTestFactory.install();
    }

    @Mock private HttpRequestResponse baseRequestResponse;
    @Mock private AuditInsertionPoint insertionPoint;
    @Mock private Http http;
    @Mock private HttpRequest request;
    @Mock private HttpService httpService;
    @Mock private ScanCheckSettings settings;

    private CurrentSelectionHolder selectionHolder;
    private McpEventLog eventLog;
    private McpActiveToolArgumentPathTraversalCheck check;

    @BeforeEach
    void setUp() {
        lenient().when(settings.isEnabled(anyString(), anyBoolean())).thenReturn(true);
        selectionHolder = new CurrentSelectionHolder();
        eventLog = spy(new McpEventLog(null));
        check = new McpActiveToolArgumentPathTraversalCheck(settings, eventLog, selectionHolder);
    }

    private static McpToolDefinition toolNamed(String name) {
        return new McpToolDefinition(name, "", "{}");
    }

    private void selectToolsByName(String... names) {
        McpToolDefinition[] tools = new McpToolDefinition[names.length];
        for (int i = 0; i < names.length; i++) {
            tools[i] = toolNamed(names[i]);
        }
        selectionHolder.set(ScanInventory.toolsOnly(List.of(tools)));
    }

    @Test
    void descriptor_exposesToolArgTraversalMetadata() {
        CheckDescriptor descriptor = check.descriptor();

        assertThat(descriptor.id()).isEqualTo("tool-arg-traversal");
        assertThat(descriptor.displayName()).isEqualTo("MCP Tool Argument Path Traversal");
        assertThat(descriptor.headlineSeverity()).isEqualTo(AuditIssueSeverity.HIGH);
        // T-deadcheck: PER_HOST-only checks with no scan-start hook were never invoked by Burp's
        // audit pipeline. PER_REQUEST drives them; internal HostDedup keeps the battery single-fire.
        assertThat(descriptor.scope()).isEqualTo(ScanCheckType.PER_REQUEST);
        assertThat(descriptor.defaultEnabled()).isTrue();
    }

    @Test
    void dedupsRepeatedInsertionPointsAgainstSameHost() {
        // PER_REQUEST dispatch fires this self-discovering check once per insertion point; HostDedup
        // must run the tools/call battery once and skip the rest.
        selectToolsByName("read_file_tool");
        stubMcpBaselineRequest();
        stubResponses(body -> {
            if (body.contains("tools/list")) {
                return successBody(TOOLS_LIST_WITH_PATH_ARG);
            }
            if (referencesPasswd(body) && containsRelativeEscape(body)) {
                return successBody(contentBody(PASSWD_FILE_CONTENT));
            }
            return successBody(INVALID_PATH_ERROR_BODY);
        });

        AuditResult first = check.doCheck(baseRequestResponse, insertionPoint, http);
        AuditResult second = check.doCheck(baseRequestResponse, insertionPoint, http);

        assertThat(first.auditIssues()).isNotEmpty();
        assertThat(second.auditIssues()).isEmpty();
    }

    @Test
    void clearSessionStateAllowsReprobeAfterReconnect() {
        // Parity with resource-traversal / unauth-discovery: a reconnect clears the per-host dedup
        // so the battery runs again against the same host.
        selectToolsByName("read_file_tool");
        stubMcpBaselineRequest();
        stubResponses(body -> {
            if (body.contains("tools/list")) {
                return successBody(TOOLS_LIST_WITH_PATH_ARG);
            }
            if (referencesPasswd(body) && containsRelativeEscape(body)) {
                return successBody(contentBody(PASSWD_FILE_CONTENT));
            }
            return successBody(INVALID_PATH_ERROR_BODY);
        });

        check.doCheck(baseRequestResponse, insertionPoint, http);
        check.clearSessionState();
        AuditResult afterReconnect = check.doCheck(baseRequestResponse, insertionPoint, http);

        assertThat(afterReconnect.auditIssues()).isNotEmpty();
    }

    @Test
    void transientHttpLayerErrorReleasesClaimSoNextInsertionPointReprobes() {
        // A transient HTTP-layer failure (timeout / dropped stream) on the FIRST insertion point
        // returns no response from every probe — including discovery. The check must release the
        // host claim so a later insertion point on the same host retries the battery.
        selectToolsByName("read_file_tool");
        stubMcpBaselineRequest();
        boolean[] firstAttempt = {true};
        stubResponses(body -> {
            if (firstAttempt[0]) {
                return transientFailure();
            }
            if (body.contains("tools/list")) {
                return successBody(TOOLS_LIST_WITH_PATH_ARG);
            }
            if (referencesPasswd(body) && containsRelativeEscape(body)) {
                return successBody(contentBody(PASSWD_FILE_CONTENT));
            }
            return successBody(INVALID_PATH_ERROR_BODY);
        });

        AuditResult first = check.doCheck(baseRequestResponse, insertionPoint, http);
        firstAttempt[0] = false;
        AuditResult second = check.doCheck(baseRequestResponse, insertionPoint, http);

        assertThat(first.auditIssues()).isEmpty();
        assertThat(second.auditIssues()).isNotEmpty();
    }

    @Test
    void doCheck_returnsEmptyWhenDisabled() {
        when(settings.isEnabled("tool-arg-traversal", true)).thenReturn(false);

        AuditResult result = check.doCheck(baseRequestResponse, insertionPoint, http);

        assertThat(result.auditIssues()).isEmpty();
        verify(http, never()).sendRequest(any(HttpRequest.class));
    }

    @Test
    void firesHighSeverityWhenPathArgReturnsPasswdContent() {
        selectToolsByName("read_file_tool");
        stubMcpBaselineRequest();
        stubResponses(body -> {
            if (body.contains("tools/list")) {
                return successBody(TOOLS_LIST_WITH_PATH_ARG);
            }
            if (referencesPasswd(body) && containsRelativeEscape(body)) {
                return successBody(contentBody(PASSWD_FILE_CONTENT));
            }
            return successBody(INVALID_PATH_ERROR_BODY);
        });

        AuditResult result = check.doCheck(baseRequestResponse, insertionPoint, http);

        assertThat(result.auditIssues()).hasSize(1);
        AuditIssue issue = result.auditIssues().get(0);
        assertThat(issue.name()).isEqualTo("MCP Tool Argument Path Traversal");
        assertThat(issue.severity()).isEqualTo(AuditIssueSeverity.HIGH);
        assertThat(issue.confidence()).isEqualTo(AuditIssueConfidence.FIRM);
        assertThat(issue.detail()).contains("read_file_tool::path");
        // Per-hit lines show the payload value + humanised file type, never the
        // internal payload label or raw FileSignature enum name.
        assertThat(issue.detail()).contains("../../../etc/passwd");
        assertThat(issue.detail()).contains("Unix password file");
        assertThat(issue.detail()).doesNotContain("dot-dot-passwd-3");
        assertThat(issue.detail()).doesNotContain("signature: PASSWD");
        assertThat(issue.detail()).doesNotContain("path-hinted");
    }

    @Test
    void relativeEscapeHitRaisesPathTraversalIssueNotFileRead() {
        // TP/accuracy: only relative ../ escapes return file content. The tool
        // broke out of its base dir, so this is genuine path traversal.
        selectToolsByName("read_file_tool");
        stubMcpBaselineRequest();
        stubResponses(body -> {
            if (body.contains("tools/list")) {
                return successBody(TOOLS_LIST_WITH_PATH_ARG);
            }
            if (containsRelativeEscape(body) && referencesPasswd(body)) {
                return successBody(contentBody(PASSWD_FILE_CONTENT));
            }
            return successBody(INVALID_PATH_ERROR_BODY);
        });

        AuditResult result = check.doCheck(baseRequestResponse, insertionPoint, http);

        assertThat(result.auditIssues()).hasSize(1);
        AuditIssue issue = result.auditIssues().get(0);
        assertThat(issue.name()).isEqualTo("MCP Tool Argument Path Traversal");
        assertThat(issue.severity()).isEqualTo(AuditIssueSeverity.HIGH);
        assertThat(issue.confidence()).isEqualTo(AuditIssueConfidence.FIRM);
        assertThat(issue.detail()).contains("read_file_tool::path");
    }

    @Test
    void absolutePathHitRaisesArbitraryFileReadIssueNotPathTraversal() {
        // FP/accuracy: only absolute-path / file:// payloads return file content.
        // No ../ escape was demonstrated, so labelling this "path traversal" would
        // mis-state the finding — it is arbitrary file read.
        selectToolsByName("read_file_tool");
        stubMcpBaselineRequest();
        stubResponses(body -> {
            if (body.contains("tools/list")) {
                return successBody(TOOLS_LIST_WITH_PATH_ARG);
            }
            if (!containsRelativeEscape(body) && referencesPasswd(body)) {
                return successBody(contentBody(PASSWD_FILE_CONTENT));
            }
            return successBody(INVALID_PATH_ERROR_BODY);
        });

        AuditResult result = check.doCheck(baseRequestResponse, insertionPoint, http);

        assertThat(result.auditIssues()).hasSize(1);
        AuditIssue issue = result.auditIssues().get(0);
        assertThat(issue.name()).isEqualTo("MCP Tool Argument Arbitrary File Read");
        assertThat(issue.name()).isNotEqualTo("MCP Tool Argument Path Traversal");
        // ABSOLUTE tier is hedged: serving an absolute path may be working-as-designed for a
        // deliberate file-exposure tool, so it is MEDIUM/TENTATIVE (mirrors the resource check),
        // not the flat HIGH/FIRM the audit flagged.
        assertThat(issue.severity()).isEqualTo(AuditIssueSeverity.MEDIUM);
        assertThat(issue.confidence()).isEqualTo(AuditIssueConfidence.TENTATIVE);
        assertThat(issue.detail()).contains("read_file_tool::path");
        assertThat(issue.detail())
                .contains("treat this as a vulnerability");
        assertThat(issue.detail()).doesNotContain("No directory-traversal escape was demonstrated");
    }

    @Test
    void encodedTwinHitAfterPlainRejectionRaisesEncodingBypassWithCertainConfidence() {
        // Decode-after-check: the literal ../ is delivered and rejected by the handler, but the
        // percent-encoded twin sails past the broken sanitizer and discloses the file.
        selectToolsByName("read_file_tool");
        stubMcpBaselineRequest();
        stubResponses(body -> {
            if (body.contains("tools/list")) {
                return successBody(TOOLS_LIST_WITH_PATH_ARG);
            }
            // Encoded twins disclose the file; the literal ../ is rejected by the handler.
            if (referencesPasswd(body) && containsEncodedEscape(body)) {
                return successBody(contentBody(PASSWD_FILE_CONTENT));
            }
            return successBody(INVALID_PATH_ERROR_BODY);
        });

        AuditResult result = check.doCheck(baseRequestResponse, insertionPoint, http);

        assertThat(result.auditIssues()).extracting(AuditIssue::name)
                .contains("MCP Tool Argument Path Traversal (Encoding Bypass)");
        AuditIssue bypass = result.auditIssues().stream()
                .filter(i -> i.name().equals("MCP Tool Argument Path Traversal (Encoding Bypass)"))
                .findFirst().orElseThrow();
        assertThat(bypass.severity()).isEqualTo(AuditIssueSeverity.HIGH);
        assertThat(bypass.confidence()).isEqualTo(AuditIssueConfidence.CERTAIN);
    }

    @Test
    void prefixSiblingNotFoundForOutOfRootPathRaisesRootBoundaryBypassMediumFirm() {
        // CVE-2025-53110: root derived from list_allowed_directories; a non-existent out-of-root
        // sibling sharing the root prefix returns a filesystem not-found (naive prefix-match passed
        // containment), which a correctly-bounded tool would have denied.
        selectToolsByName("read_file_tool");
        stubMcpBaselineRequest();
        stubResponses(body -> {
            if (body.contains("tools/list")) {
                return successBody(TOOLS_LIST_WITH_LIST_ALLOWED_DIRS);
            }
            if (body.contains("list_allowed_directories")) {
                return successBody(contentBody("Allowed directories:\n/srv/workspace"));
            }
            // The deny-control (a non-prefix out-of-root path) is access-denied; only the
            // prefix-sharing sibling returns a filesystem not-found.
            if (body.contains("mcpscan-nonexistent")) {
                return toolErrorBody("Access denied - path outside allowed directories: not in /srv/workspace");
            }
            if (body.contains("workspace_mcpscan_")) {
                return toolErrorBody("Error: Parent directory does not exist: /srv/workspace_mcpscan_ab");
            }
            return successBody(INVALID_PATH_ERROR_BODY);
        });

        AuditResult result = check.doCheck(baseRequestResponse, insertionPoint, http);

        AuditIssue boundary = result.auditIssues().stream()
                .filter(i -> i.name().equals("MCP Tool Argument Path Traversal (Root Boundary Bypass)"))
                .findFirst().orElseThrow();
        assertThat(boundary.severity()).isEqualTo(AuditIssueSeverity.MEDIUM);
        assertThat(boundary.confidence()).isEqualTo(AuditIssueConfidence.FIRM);
        assertThat(boundary.detail()).contains("CVE-2025-53110");
        assertThat(boundary.detail()).contains("read_file_tool::path");
    }

    @Test
    void prefixSiblingAccessDeniedForOutOfRootPathRaisesNoBoundaryBypass() {
        // Negative control: a correctly-bounded tool denies the out-of-root sibling before touching
        // the filesystem, so the prefix-match oracle stays silent (no false positive).
        selectToolsByName("read_file_tool");
        stubMcpBaselineRequest();
        stubResponses(body -> {
            if (body.contains("tools/list")) {
                return successBody(TOOLS_LIST_WITH_LIST_ALLOWED_DIRS);
            }
            if (body.contains("list_allowed_directories")) {
                return successBody(contentBody("Allowed directories:\n/srv/workspace"));
            }
            // Every out-of-root path (sibling or derivation probe) is access-denied.
            return toolErrorBody("Access denied - path outside allowed directories: not in /srv/workspace");
        });

        AuditResult result = check.doCheck(baseRequestResponse, insertionPoint, http);

        assertThat(result.auditIssues()).extracting(AuditIssue::name)
                .doesNotContain("MCP Tool Argument Path Traversal (Root Boundary Bypass)");
    }

    @Test
    void safeToolThatDeniesEveryEscapeRaisesNoIssue() {
        // FP-resistance: a correctly-sandboxed tool rejects ../, encoded twins, absolute paths and
        // prefix-sibling escapes alike — the check must stay silent.
        selectToolsByName("read_file_tool");
        stubMcpBaselineRequest();
        stubResponses(body -> {
            if (body.contains("tools/list")) {
                return successBody(TOOLS_LIST_WITH_LIST_ALLOWED_DIRS);
            }
            if (body.contains("list_allowed_directories")) {
                return successBody(contentBody("Allowed directories:\n/srv/workspace"));
            }
            return toolErrorBody("Access denied - path outside allowed directories: not in /srv/workspace");
        });

        AuditResult result = check.doCheck(baseRequestResponse, insertionPoint, http);

        assertThat(result.auditIssues()).isEmpty();
    }

    @Test
    void emitsBothIssuesWhenBothTiersHit() {
        selectToolsByName("read_file_tool");
        stubMcpBaselineRequest();
        stubResponses(body -> {
            if (body.contains("tools/list")) {
                return successBody(TOOLS_LIST_WITH_PATH_ARG);
            }
            if (referencesPasswd(body)) {
                return successBody(contentBody(PASSWD_FILE_CONTENT));
            }
            return successBody(INVALID_PATH_ERROR_BODY);
        });

        AuditResult result = check.doCheck(baseRequestResponse, insertionPoint, http);

        assertThat(result.auditIssues()).extracting(AuditIssue::name)
                .contains("MCP Tool Argument Path Traversal", "MCP Tool Argument Arbitrary File Read");
    }

    @Test
    void firesWhenDescriptionHintsAtPathEvenIfNameDoesNot() {
        selectToolsByName("open_report");
        stubMcpBaselineRequest();
        stubResponses(body -> {
            if (body.contains("tools/list")) {
                return successBody(TOOLS_LIST_WITH_DESCRIPTION_HINT);
            }
            if (referencesPasswd(body) && containsRelativeEscape(body)) {
                return successBody(contentBody(PASSWD_FILE_CONTENT));
            }
            return successBody(INVALID_PATH_ERROR_BODY);
        });

        AuditResult result = check.doCheck(baseRequestResponse, insertionPoint, http);

        assertThat(result.auditIssues()).hasSize(1);
        assertThat(result.auditIssues().get(0).detail()).contains("open_report::seed");
    }

    @Test
    void consolidatesMultipleHitsForSameToolAndArgIntoSingleIssue() {
        selectToolsByName("read_file_tool");
        stubMcpBaselineRequest();
        stubResponses(body -> {
            if (body.contains("tools/list")) {
                return successBody(TOOLS_LIST_WITH_PATH_ARG);
            }
            if (referencesPasswd(body) && containsRelativeEscape(body)) {
                return successBody(contentBody(PASSWD_FILE_CONTENT));
            }
            if (body.contains("win.ini") && containsRelativeEscape(body)) {
                return successBody(contentBody(WIN_INI_FILE_CONTENT));
            }
            return successBody(INVALID_PATH_ERROR_BODY);
        });

        AuditResult result = check.doCheck(baseRequestResponse, insertionPoint, http);

        assertThat(result.auditIssues()).hasSize(1);
        AuditIssue issue = result.auditIssues().get(0);
        assertThat(issue.requestResponses()).hasSizeGreaterThanOrEqualTo(2);
    }

    @Test
    void emitsOneIssuePerToolAndArgumentPair() {
        selectToolsByName("read_file_tool", "load_doc");
        stubMcpBaselineRequest();
        stubResponses(body -> {
            if (body.contains("tools/list")) {
                return successBody(TOOLS_LIST_TWO_PATH_TOOLS);
            }
            if (referencesPasswd(body) && containsRelativeEscape(body)) {
                return successBody(contentBody(PASSWD_FILE_CONTENT));
            }
            return successBody(INVALID_PATH_ERROR_BODY);
        });

        AuditResult result = check.doCheck(baseRequestResponse, insertionPoint, http);

        assertThat(result.auditIssues()).hasSize(2);
        assertThat(result.auditIssues()).extracting(AuditIssue::detail)
                .anyMatch(detail -> detail.contains("read_file_tool::path"))
                .anyMatch(detail -> detail.contains("load_doc::filename"));
    }

    @Test
    void skipsWhenNoToolsHavePathHintedArgs() {
        selectToolsByName("query_user");
        stubMcpBaselineRequest();
        stubResponses(body -> {
            if (body.contains("tools/list")) {
                return successBody(TOOLS_LIST_WITHOUT_PATH_ARG);
            }
            return successBody(contentBody(PASSWD_FILE_CONTENT));
        });

        AuditResult result = check.doCheck(baseRequestResponse, insertionPoint, http);

        assertThat(result.auditIssues()).isEmpty();
    }

    @Test
    void skipsWhenToolsListIsEmpty() {
        selectToolsByName("anything");
        stubMcpBaselineRequest();
        stubResponses(body -> successBody(TOOLS_LIST_EMPTY));

        AuditResult result = check.doCheck(baseRequestResponse, insertionPoint, http);

        assertThat(result.auditIssues()).isEmpty();
    }

    @Test
    void skipsWhenResponsesDoNotMatchAnySignature() {
        selectToolsByName("read_file_tool");
        stubMcpBaselineRequest();
        stubResponses(body -> {
            if (body.contains("tools/list")) {
                return successBody(TOOLS_LIST_WITH_PATH_ARG);
            }
            return successBody(contentBody("nothing sensitive here"));
        });

        AuditResult result = check.doCheck(baseRequestResponse, insertionPoint, http);

        assertThat(result.auditIssues()).isEmpty();
    }

    @Test
    void doesNotFireForNonMcpRequest() {
        when(baseRequestResponse.request()).thenReturn(request);
        when(request.method()).thenReturn("POST");
        when(request.bodyToString()).thenReturn("{\"hello\":\"world\"}");

        AuditResult result = check.doCheck(baseRequestResponse, insertionPoint, http);

        assertThat(result.auditIssues()).isEmpty();
        verify(http, never()).sendRequest(any(HttpRequest.class));
    }

    @Test
    void doesNotFireWhenIsErrorTrueDespitePasswdContent() {
        selectToolsByName("read_file_tool");
        stubMcpBaselineRequest();
        String passwdInErrorBody = "{\"jsonrpc\":\"2.0\",\"result\":{\"content\":[{\"type\":\"text\",\"text\":\""
                + jsonEscape(PASSWD_FILE_CONTENT) + "\"}],\"isError\":true}}";
        stubResponses(body -> {
            if (body.contains("tools/list")) {
                return successBody(TOOLS_LIST_WITH_PATH_ARG);
            }
            return successBody(passwdInErrorBody);
        });

        AuditResult result = check.doCheck(baseRequestResponse, insertionPoint, http);

        assertThat(result.auditIssues()).isEmpty();
    }

    @Test
    void doesNotFireForSignatureWithoutMatchingPayload() {
        selectToolsByName("read_file_tool");
        stubMcpBaselineRequest();
        stubResponses(body -> {
            if (body.contains("tools/list")) {
                return successBody(TOOLS_LIST_WITH_PATH_ARG);
            }
            return successBody(contentBody(HOSTS_FILE_CONTENT));
        });

        AuditResult result = check.doCheck(baseRequestResponse, insertionPoint, http);

        // HOSTS not in payload signatures — passwd is matched and so is win_ini,
        // but HOSTS is intentionally absent from payloads, so no hit expected.
        assertThat(result.auditIssues()).isEmpty();
    }

    @Test
    void skipsWhenNoToolsSelected_evenIfDiscoveryReturnsPathTools() {
        // Selection holder is empty (default state). The check must return early
        // BEFORE issuing any HTTP request, even though discovery would have
        // surfaced a path-like argument.
        stubMcpBaselineRequest();

        AuditResult result = check.doCheck(baseRequestResponse, insertionPoint, http);

        assertThat(result.auditIssues()).isEmpty();
        verify(http, never()).sendRequest(any(HttpRequest.class));
        verify(eventLog).info(contains("no tools selected"));
    }

    @Test
    void filtersDiscoveredToolsToUserSelection() {
        // Discovery returns BOTH read_file_tool and load_doc, but the user only
        // selected read_file_tool — load_doc must never be probed.
        selectToolsByName("read_file_tool");
        stubMcpBaselineRequest();
        stubResponses(body -> {
            if (body.contains("tools/list")) {
                return successBody(TOOLS_LIST_TWO_PATH_TOOLS);
            }
            if (referencesPasswd(body) && containsRelativeEscape(body)) {
                return successBody(contentBody(PASSWD_FILE_CONTENT));
            }
            return successBody(INVALID_PATH_ERROR_BODY);
        });

        AuditResult result = check.doCheck(baseRequestResponse, insertionPoint, http);

        assertThat(result.auditIssues()).hasSize(1);
        assertThat(result.auditIssues().get(0).detail()).contains("read_file_tool::path");
        assertThat(result.auditIssues().get(0).detail()).doesNotContain("load_doc");
        verify(http, never()).sendRequest(argThat(req -> req != null && req.bodyToString().contains("\"load_doc\"")));
    }

    @Test
    void firesForNullableStringPathArgumentSchema() {
        // Real-world tool schemas frequently emit nullable strings as
        // {"type": ["string", "null"]} (FastMCP, langchain4j MCP) — the legacy
        // schema.path("type").asText().equals("string") check would skip them.
        selectToolsByName("read_file_tool");
        stubMcpBaselineRequest();
        stubResponses(body -> {
            if (body.contains("tools/list")) {
                return successBody(TOOLS_LIST_NULLABLE_PATH_ARG);
            }
            if (referencesPasswd(body) && containsRelativeEscape(body)) {
                return successBody(contentBody(PASSWD_FILE_CONTENT));
            }
            return successBody(INVALID_PATH_ERROR_BODY);
        });

        AuditResult result = check.doCheck(baseRequestResponse, insertionPoint, http);

        assertThat(result.auditIssues()).hasSize(1);
        assertThat(result.auditIssues().get(0).detail()).contains("read_file_tool::path");
    }

    private static boolean referencesPasswd(String body) {
        return body.contains("etc/passwd") || body.contains("etc%2fpasswd")
                || body.contains("%2fpasswd") || body.contains("etc%252fpasswd");
    }

    private static boolean containsRelativeEscape(String body) {
        // Mirrors the dot-dot escapes that distinguish the TRAVERSAL tier from the
        // ABSOLUTE tier (rooted /etc/passwd, file:///etc/passwd).
        String lower = body.toLowerCase();
        return lower.contains("../") || lower.contains("..\\\\")
                || lower.contains("..%2f") || lower.contains("..%5c") || lower.contains("..%252f")
                || lower.contains("%2e%2e") || lower.contains("....//")
                // Overlong UTF-8 encoding of `../` (%c0%ae%c0%ae%c0%af) — a relative escape the
                // simpler markers above miss; a real handler decodes it to a traversal.
                || lower.contains("%c0%ae");
    }

    private static boolean containsEncodedEscape(String body) {
        // Encoded traversal twins only (excludes the literal `../`), so a stub can serve the file
        // for the encoded payloads while rejecting the plain one — the decode-after-check shape.
        String lower = body.toLowerCase();
        return lower.contains("..%2f") || lower.contains("..%5c") || lower.contains("..%252f")
                || lower.contains("%2e%2e") || lower.contains("....//") || lower.contains("%c0%ae");
    }

    private static HttpRequestResponse toolErrorBody(String message) {
        return successBody("{\"jsonrpc\":\"2.0\",\"result\":{\"isError\":true,\"content\":[{\"type\":\"text\","
                + "\"text\":\"" + jsonEscape(message) + "\"}]}}");
    }

    private void stubMcpBaselineRequest() {
        when(baseRequestResponse.request()).thenReturn(request);
        when(request.method()).thenReturn("POST");
        when(request.bodyToString()).thenReturn(MCP_REQUEST_BODY);
        lenient().when(request.httpService()).thenReturn(httpService);
        lenient().when(httpService.secure()).thenReturn(false);
        lenient().when(httpService.host()).thenReturn("localhost");
        lenient().when(httpService.port()).thenReturn(8080);
    }

    private void stubResponses(Function<String, HttpRequestResponse> responseFn) {
        when(request.withBody(anyString())).thenAnswer(invocation -> requestWithBody(invocation.getArgument(0)));
        when(http.sendRequest(any(HttpRequest.class))).thenAnswer(invocation -> {
            HttpRequest sent = invocation.getArgument(0);
            return responseFn.apply(sent.bodyToString());
        });
    }

    private static HttpRequest requestWithBody(String body) {
        HttpRequest mutated = mock(HttpRequest.class);
        lenient().when(mutated.bodyToString()).thenReturn(body);
        return mutated;
    }

    private static HttpRequestResponse successBody(String responseBody) {
        HttpRequestResponse rr = mock(HttpRequestResponse.class);
        HttpResponse response = mock(HttpResponse.class);
        lenient().when(rr.response()).thenReturn(response);
        lenient().when(response.statusCode()).thenReturn((short) 200);
        lenient().when(response.bodyToString()).thenReturn(responseBody);
        return rr;
    }

    /** A transport-layer failure: Burp returns an HttpRequestResponse with a null response. */
    private static HttpRequestResponse transientFailure() {
        HttpRequestResponse rr = mock(HttpRequestResponse.class);
        lenient().when(rr.response()).thenReturn(null);
        return rr;
    }

    private static String contentBody(String text) {
        return "{\"jsonrpc\":\"2.0\",\"result\":{\"content\":[{\"type\":\"text\",\"text\":\""
                + jsonEscape(text) + "\"}]}}";
    }

    private static String jsonEscape(String value) {
        return value.replace("\\", "\\\\")
                .replace("\"", "\\\"")
                .replace("\n", "\\n")
                .replace("\r", "\\r");
    }
}
