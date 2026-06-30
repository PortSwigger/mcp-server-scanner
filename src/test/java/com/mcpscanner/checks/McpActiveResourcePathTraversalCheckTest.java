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
import com.mcpscanner.mcp.McpResourceDefinition;
import com.mcpscanner.scan.ScanInventory;
import com.mcpscanner.testutil.MontoyaTestFactory;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.util.ArrayList;
import java.util.List;
import java.util.function.Function;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyBoolean;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.mockingDetails;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class McpActiveResourcePathTraversalCheckTest {

    private static final String MCP_REQUEST_BODY = "{\"jsonrpc\":\"2.0\",\"method\":\"tools/call\"}";

    private static final String PASSWD_FILE_CONTENT =
            "root:x:0:0:root:/root:/bin/bash\n"
                    + "daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n"
                    + "bin:x:2:2:bin:/bin:/usr/sbin/nologin\n";
    private static final String HOSTS_FILE_CONTENT =
            "127.0.0.1 localhost\n::1 localhost\n";

    private static final String INVALID_URI_ERROR_BODY =
            "{\"jsonrpc\":\"2.0\",\"error\":{\"code\":-32602,\"message\":\"Invalid URI\"}}";
    private static final String UNKNOWN_RESOURCE_ERROR_BODY =
            "{\"jsonrpc\":\"2.0\",\"error\":{\"code\":0,\"message\":\"Unknown resource: file:///etc/passwd\"}}";
    private static final String EMPTY_TEMPLATES_RESPONSE =
            "{\"jsonrpc\":\"2.0\",\"result\":{\"resourceTemplates\":[]}}";
    private static final String EMPTY_RESOURCES_RESPONSE =
            "{\"jsonrpc\":\"2.0\",\"result\":{\"resources\":[]}}";

    // The check now sends ONE canonical deep escape per family (../ repeated DEEP_LEVELS times);
    // excess ../ clamps at the filesystem root, so a single deep prefix covers shallow + deep roots.
    // These mirror the exact escape the check emits so the stub matchers stay anchored to it.
    private static final String DEEP_PLAIN_ESCAPE = "../".repeat(TraversalEscapes.DEEP_LEVELS);
    private static final String DEEP_PCT_SLASH_ESCAPE = "..%2f".repeat(TraversalEscapes.DEEP_LEVELS);

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

    private McpActiveResourcePathTraversalCheck check;

    @BeforeEach
    void setUp() {
        lenient().when(settings.isEnabled(anyString(), anyBoolean())).thenReturn(true);
        check = new McpActiveResourcePathTraversalCheck(settings);
    }

    @Test
    void descriptor_exposesResourceTraversalMetadata() {
        CheckDescriptor descriptor = check.descriptor();

        assertThat(descriptor.id()).isEqualTo("resource-traversal");
        assertThat(descriptor.displayName()).isEqualTo("MCP Resource Path Traversal");
        assertThat(descriptor.headlineSeverity()).isEqualTo(AuditIssueSeverity.HIGH);
        // T-deadcheck: PER_HOST-only checks with no scan-start hook were never invoked by Burp's
        // audit pipeline. PER_REQUEST drives them; internal HostDedup keeps the battery single-fire.
        assertThat(descriptor.scope()).isEqualTo(ScanCheckType.PER_REQUEST);
        assertThat(descriptor.defaultEnabled()).isTrue();
    }

    @Test
    void dedupsRepeatedInsertionPointsAgainstSameHost() {
        // PER_REQUEST dispatch fires this self-discovering check once per insertion point; HostDedup
        // must run the resources/read battery once and skip the rest.
        stubMcpBaselineRequest();
        stubServer(absoluteOnlyServer());

        AuditResult first = check.doCheck(baseRequestResponse, insertionPoint, http);
        AuditResult second = check.doCheck(baseRequestResponse, insertionPoint, http);

        assertThat(first.auditIssues()).isNotEmpty();
        assertThat(second.auditIssues()).isEmpty();
    }

    @Test
    void transientHttpLayerErrorReleasesClaimSoNextInsertionPointReprobes() {
        // A transient HTTP-layer failure (timeout / dropped stream) on the FIRST insertion point
        // returns no response from every probe. The check must release the host claim so a later
        // insertion point on the same host retries — otherwise the battery is silently disabled for
        // the rest of the scan.
        stubMcpBaselineRequest();
        Function<String, HttpRequestResponse> working = absoluteOnlyServer();
        boolean[] firstAttempt = {true};
        stubServer(body -> firstAttempt[0] ? transientFailure() : working.apply(body));

        AuditResult first = check.doCheck(baseRequestResponse, insertionPoint, http);
        firstAttempt[0] = false;
        AuditResult second = check.doCheck(baseRequestResponse, insertionPoint, http);

        assertThat(first.auditIssues()).isEmpty();
        assertThat(second.auditIssues()).isNotEmpty();
    }

    @Test
    void cleanNegativeKeepsClaimSoNextInsertionPointSkips() {
        // A reachable server that answers cleanly with no vulnerability must KEEP the claim so the
        // battery does not re-run on every one of the ~29 insertion points in a scan. The second
        // invocation must send no further probes.
        stubMcpBaselineRequest();
        stubServer(body -> successBody(INVALID_URI_ERROR_BODY));

        AuditResult first = check.doCheck(baseRequestResponse, insertionPoint, http);
        int probesAfterFirst = mockingDetails(http).getInvocations().size();
        AuditResult second = check.doCheck(baseRequestResponse, insertionPoint, http);

        assertThat(first.auditIssues()).isEmpty();
        assertThat(second.auditIssues()).isEmpty();
        // No re-probe: the second invocation issued no new sendRequest calls.
        assertThat(mockingDetails(http).getInvocations().size()).isEqualTo(probesAfterFirst);
    }

    @Test
    void clearSessionStateAllowsReprobeAfterReconnect() {
        stubMcpBaselineRequest();
        stubServer(absoluteOnlyServer());

        check.doCheck(baseRequestResponse, insertionPoint, http);
        check.clearSessionState();
        AuditResult afterReconnect = check.doCheck(baseRequestResponse, insertionPoint, http);

        assertThat(afterReconnect.auditIssues()).isNotEmpty();
    }

    @Test
    void doCheck_returnsEmptyWhenDisabled() {
        when(settings.isEnabled("resource-traversal", true)).thenReturn(false);

        AuditResult result = check.doCheck(baseRequestResponse, insertionPoint, http);

        assertThat(result.auditIssues()).isEmpty();
        verify(http, never()).sendRequest(any(HttpRequest.class));
    }

    @Test
    void engages_onResourcesReadBaseline() {
        stubMcpBaselineRequestWithBody(
                "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"resources/read\",\"params\":{\"uri\":\"file:///x\"}}");
        stubServer(absoluteOnlyServer());

        AuditResult result = check.doCheck(baseRequestResponse, insertionPoint, http);

        assertThat(onlyIssue(result).name()).isEqualTo("MCP Resource Arbitrary File Read");
    }

    @Test
    void engages_onPromptsGetBaseline() {
        stubMcpBaselineRequestWithBody(
                "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"prompts/get\",\"params\":{\"name\":\"p\"}}");
        stubServer(absoluteOnlyServer());

        AuditResult result = check.doCheck(baseRequestResponse, insertionPoint, http);

        assertThat(onlyIssue(result).name()).isEqualTo("MCP Resource Arbitrary File Read");
    }

    // -------- ABSOLUTE tier: hedged, demoted to MEDIUM/TENTATIVE --------

    @Test
    void absoluteFileReadIsHedgedMediumTentative() {
        stubMcpBaselineRequest();
        stubServer(absoluteOnlyServer());

        AuditResult result = check.doCheck(baseRequestResponse, insertionPoint, http);

        AuditIssue issue = onlyIssue(result);
        assertThat(issue.name()).isEqualTo("MCP Resource Arbitrary File Read");
        assertThat(issue.severity()).isEqualTo(AuditIssueSeverity.MEDIUM);
        assertThat(issue.confidence()).isEqualTo(AuditIssueConfidence.TENTATIVE);
        assertThat(issue.detail()).contains("file:///etc/passwd");
        assertThat(issue.detail()).contains("Unix password file");
        assertThat(issue.detail()).contains("working-as-designed");
        assertThat(issue.detail()).contains("verify against the intended sandbox root");
        assertThat(issue.detail()).doesNotContain("passwd-raw");
    }

    @Test
    void workingAsDesignedFileServerNeverFiresHigh() {
        stubMcpBaselineRequest();
        stubServer(absoluteOnlyServer());

        AuditResult result = check.doCheck(baseRequestResponse, insertionPoint, http);

        assertThat(result.auditIssues())
                .allSatisfy(issue -> assertThat(issue.severity()).isNotEqualTo(AuditIssueSeverity.HIGH));
        assertThat(result.auditIssues()).hasSize(1);
        assertThat(onlyIssue(result).confidence()).isEqualTo(AuditIssueConfidence.TENTATIVE);
    }

    // -------- TRAVERSAL tier: plain ../ escape from a discovered root --------

    @Test
    void plainEscapeFromDiscoveredRootFiresTraversalHigh() {
        stubMcpBaselineRequest();
        stubServer(body -> {
            if (isResourcesList(body)) {
                return successBody(resourcesListWith("file:///workspace/readme.txt"));
            }
            if (isTemplatesList(body)) {
                return successBody(EMPTY_TEMPLATES_RESPONSE);
            }
            // Root-join bug: plain ../ escape from the discovered root resolves to passwd.
            if (body.contains("file:///workspace/" + DEEP_PLAIN_ESCAPE + "etc/passwd")) {
                return successBody(contentsBody(PASSWD_FILE_CONTENT));
            }
            return successBody(INVALID_URI_ERROR_BODY);
        });

        AuditResult result = check.doCheck(baseRequestResponse, insertionPoint, http);

        AuditIssue issue = issueNamed(result, "MCP Resource Path Traversal");
        assertThat(issue.severity()).isEqualTo(AuditIssueSeverity.HIGH);
        assertThat(issue.confidence()).isEqualTo(AuditIssueConfidence.FIRM);
    }

    @Test
    void multFetchShape_embeddedTemplateInResourcesList_firesTraversalHigh() {
        // Real-world reproduction of @lmcc-dev/mult-fetch-mcp-server 1.3.2 (plain MCP SDK, not
        // FastMCP): the file:///src/{path} template is advertised INSIDE the resources/list
        // response, and resources/templates/list returns -32601. The handler joins the raw
        // remainder under a deeply-installed project root, so a LITERAL ../ escape reaches the
        // filesystem (literal slashes are NOT dropped — non-FastMCP routing). Only a deep
        // traversal reaches the filesystem root from a deep install.
        stubMcpBaselineRequest();
        stubServer(body -> {
            if (isTemplatesList(body)) {
                return successBody(
                        "{\"jsonrpc\":\"2.0\",\"error\":{\"code\":-32601,\"message\":\"Method not found\"}}");
            }
            if (isResourcesList(body)) {
                return successBody("{\"jsonrpc\":\"2.0\",\"result\":{\"resources\":"
                        + "[{\"uri\":\"file:///logs/debug\"}],"
                        + "\"resourceTemplates\":[{\"uriTemplate\":\"file:///src/{path}\"}]}}");
            }
            // Deeply-installed project root: only a deep literal ../ escape reaches /etc/passwd.
            if (deepLiteralTraversalToPasswd(body, "file:///src/")) {
                return successBody(contentsBody(PASSWD_FILE_CONTENT));
            }
            // Every shallow probe / concrete log URI / absolute read is a routing/not-found miss.
            return successBody(UNKNOWN_RESOURCE_ERROR_BODY);
        });

        AuditResult result = check.doCheck(baseRequestResponse, insertionPoint, http);

        AuditIssue issue = issueNamed(result, "MCP Resource Path Traversal");
        assertThat(issue.severity()).isEqualTo(AuditIssueSeverity.HIGH);
        assertThat(issue.confidence()).isEqualTo(AuditIssueConfidence.FIRM);
        assertThat(issue.detail()).contains("file:///src/");
    }

    @Test
    void deeplyInstalledSandboxedServerWithEmbeddedTemplateFiresNothing() {
        // No-FP twin of the mult-fetch shape: same deep install + embedded template, but the
        // handler canonicalises and contains every path under the root. No probe (shallow OR deep,
        // literal OR encoded) escapes, so the corroborated FileSignature oracle never matches.
        stubMcpBaselineRequest();
        stubServer(body -> {
            if (isTemplatesList(body)) {
                return successBody(
                        "{\"jsonrpc\":\"2.0\",\"error\":{\"code\":-32601,\"message\":\"Method not found\"}}");
            }
            if (isResourcesList(body)) {
                return successBody("{\"jsonrpc\":\"2.0\",\"result\":{\"resources\":"
                        + "[{\"uri\":\"file:///logs/debug\"}],"
                        + "\"resourceTemplates\":[{\"uriTemplate\":\"file:///src/{path}\"}]}}");
            }
            // Correctly sandboxed: every escape attempt is rejected.
            return successBody(errorMessageBody("path is outside the resource root"));
        });

        AuditResult result = check.doCheck(baseRequestResponse, insertionPoint, http);

        assertThat(result.auditIssues()).isEmpty();
    }

    @Test
    void directoryRootResourceWithNaiveStartsWithGuardFiresTraversalHigh() {
        // DiggAI obsidian-mcp shape: the server lists the vault ROOT DIRECTORY itself as the only
        // resource and guards reads with a naive UN-normalized startsWith(full-root). A literal ../
        // that RETAINS the full discovered root as a string prefix passes the guard but OS-resolves
        // to /etc/passwd. The stripped-parent base drops the .obsidian-vault segment and fails the
        // guard; only the verbatim-base escape (rooted at the discovered URI itself) gets through.
        String vaultRoot = "file:///app/data/notes/.obsidian-vault";
        stubMcpBaselineRequest();
        stubServer(body -> {
            if (isResourcesList(body)) {
                return successBody(resourcesListWith(vaultRoot));
            }
            if (isTemplatesList(body)) {
                return successBody(EMPTY_TEMPLATES_RESPONSE);
            }
            // Naive startsWith(full-root): a literal ../ that keeps the full vault root prefix passes
            // the guard and OS-resolves outside it -> passwd. A probe missing the full prefix is denied.
            if (body.contains(vaultRoot + "/" + DEEP_PLAIN_ESCAPE + "etc/passwd")) {
                return successBody(contentsBody(PASSWD_FILE_CONTENT));
            }
            return successBody(errorMessageBody("path is outside the allowed root"));
        });

        AuditResult result = check.doCheck(baseRequestResponse, insertionPoint, http);

        AuditIssue issue = issueNamed(result, "MCP Resource Path Traversal");
        assertThat(issue.severity()).isEqualTo(AuditIssueSeverity.HIGH);
        assertThat(issue.confidence()).isEqualTo(AuditIssueConfidence.FIRM);
        assertThat(issue.detail()).contains(vaultRoot);
    }

    @Test
    void singleSegmentDirectoryRootResourceWithNaiveStartsWithGuardFiresTraversalHigh() {
        // FN fix (Codex review): the server lists the directory ROOT as a SINGLE-SEGMENT URI
        // (file:///workspace, no parent to strip) and guards with a naive startsWith(full-root). A
        // literal ../ retaining the full root prefix passes the guard but OS-resolves to /etc/passwd.
        String singleSegmentRoot = "file:///workspace";
        stubMcpBaselineRequest();
        stubServer(body -> {
            if (isResourcesList(body)) {
                return successBody(resourcesListWith(singleSegmentRoot));
            }
            if (isTemplatesList(body)) {
                return successBody(EMPTY_TEMPLATES_RESPONSE);
            }
            if (body.contains(singleSegmentRoot + "/" + DEEP_PLAIN_ESCAPE + "etc/passwd")) {
                return successBody(contentsBody(PASSWD_FILE_CONTENT));
            }
            return successBody(errorMessageBody("path is outside the allowed root"));
        });

        AuditResult result = check.doCheck(baseRequestResponse, insertionPoint, http);

        AuditIssue issue = issueNamed(result, "MCP Resource Path Traversal");
        assertThat(issue.severity()).isEqualTo(AuditIssueSeverity.HIGH);
        assertThat(issue.confidence()).isEqualTo(AuditIssueConfidence.FIRM);
        assertThat(issue.detail()).contains(singleSegmentRoot);
    }

    @Test
    void sandboxedSingleSegmentDirectoryRootResourceFiresNothing() {
        // No-FP twin: same single-segment directory root, but every escape is contained.
        stubMcpBaselineRequest();
        stubServer(body -> {
            if (isResourcesList(body)) {
                return successBody(resourcesListWith("file:///workspace"));
            }
            if (isTemplatesList(body)) {
                return successBody(EMPTY_TEMPLATES_RESPONSE);
            }
            return successBody(errorMessageBody("path is outside the allowed root"));
        });

        AuditResult result = check.doCheck(baseRequestResponse, insertionPoint, http);

        assertThat(result.auditIssues()).isEmpty();
    }

    @Test
    void sandboxedDirectoryRootResourceFiresNothing() {
        // No-FP twin: same directory-root resource, but the handler canonicalises and contains every
        // path under the root. No verbatim-base or stripped-parent escape resolves out, so the
        // corroborated FileSignature oracle never matches and nothing fires.
        stubMcpBaselineRequest();
        stubServer(body -> {
            if (isResourcesList(body)) {
                return successBody(resourcesListWith("file:///app/data/notes/.obsidian-vault"));
            }
            if (isTemplatesList(body)) {
                return successBody(EMPTY_TEMPLATES_RESPONSE);
            }
            return successBody(errorMessageBody("path is outside the allowed root"));
        });

        AuditResult result = check.doCheck(baseRequestResponse, insertionPoint, http);

        assertThat(result.auditIssues()).isEmpty();
    }

    // -------- ENCODING_BYPASS tier: differential — plain rejected, encoded accepted --------

    @Test
    void encodingDifferentialFiresEncodingBypassCertain() {
        stubMcpBaselineRequest();
        stubServer(body -> {
            if (isResourcesList(body)) {
                return successBody(resourcesListWith("file:///workspace/readme.txt"));
            }
            if (isTemplatesList(body)) {
                return successBody(EMPTY_TEMPLATES_RESPONSE);
            }
            // Decode-after-check: literal ../ rejected, percent-encoded twin slips through.
            if (body.contains("file:///workspace/" + DEEP_PCT_SLASH_ESCAPE + "etc%2fpasswd")) {
                return successBody(contentsBody(PASSWD_FILE_CONTENT));
            }
            return successBody(INVALID_URI_ERROR_BODY);
        });

        AuditResult result = check.doCheck(baseRequestResponse, insertionPoint, http);

        AuditIssue issue = issueNamed(result, "MCP Resource Path Traversal (Encoding Bypass)");
        assertThat(issue.severity()).isEqualTo(AuditIssueSeverity.HIGH);
        assertThat(issue.confidence()).isEqualTo(AuditIssueConfidence.CERTAIN);
        assertThat(issue.detail()).contains("rejected a literal ../ escape");
    }

    @Test
    void encodedHitWithPlainNeverDeliveredFiresTraversalNotEncodingBypass() {
        // FP guard: when the literal ../ is never DELIVERED to the handler (the routing layer
        // drops literal-slash URIs and answers "Unknown resource", as FastMCP's resource
        // templates do), an encoded-only hit is an ordinary traversal — not proof of a broken
        // sanitizer. The check must report TRAVERSAL, never over-claim ENCODING_BYPASS.
        stubMcpBaselineRequest();
        stubServer(body -> {
            if (isResourcesList(body)) {
                return successBody(EMPTY_RESOURCES_RESPONSE);
            }
            if (isTemplatesList(body)) {
                return successBody(
                        "{\"jsonrpc\":\"2.0\",\"result\":{\"resourceTemplates\":"
                                + "[{\"uriTemplate\":\"rooted:///{path}\"}]}}");
            }
            if (body.contains("rooted:///" + DEEP_PCT_SLASH_ESCAPE + "etc%2fpasswd")) {
                return successBody(contentsBody(PASSWD_FILE_CONTENT));
            }
            // Literal ../ URI is rejected at the routing layer, never reaching the handler.
            return successBody(UNKNOWN_RESOURCE_ERROR_BODY);
        });

        AuditResult result = check.doCheck(baseRequestResponse, insertionPoint, http);

        assertThat(result.auditIssues()).extracting(AuditIssue::name)
                .contains("MCP Resource Path Traversal")
                .doesNotContain("MCP Resource Path Traversal (Encoding Bypass)");
        assertThat(issueNamed(result, "MCP Resource Path Traversal").confidence())
                .isEqualTo(AuditIssueConfidence.FIRM);
    }

    // -------- PREFIX_SIBLING tier: CVE-2025-53110 root-boundary bypass --------

    @Test
    void prefixSiblingEscapeFiresRootBoundaryBypassMedium() {
        // CVE-2025-53110 via the no-planted-secret error-differential: the deny-control (a
        // non-prefix out-of-root URI) is access-denied while the prefix-sharing non-existent sibling
        // returns a filesystem not-found — proving naive startsWith(root) containment.
        stubMcpBaselineRequest();
        stubServer(body -> {
            if (isResourcesList(body)) {
                // Leak the root via a concrete file-rooted URI so the prefix-sibling probe derives it.
                return successBody(resourcesListWith("prefixmatch:///srv/workspace/canary.txt"));
            }
            if (isTemplatesList(body)) {
                return successBody(EMPTY_TEMPLATES_RESPONSE);
            }
            if (body.contains("mcpscan-nonexistent")) {
                return successBody(errorMessageBody("path is outside the resource root"));
            }
            if (body.contains("workspace_mcpscan_")) {
                return successBody(errorMessageBody("[Errno 2] No such file or directory: '/srv/...'"));
            }
            return successBody(INVALID_URI_ERROR_BODY);
        });

        AuditResult result = check.doCheck(baseRequestResponse, insertionPoint, http);

        AuditIssue issue = issueNamed(result, "MCP Resource Path Traversal (Root Boundary Bypass)");
        assertThat(issue.severity()).isEqualTo(AuditIssueSeverity.MEDIUM);
        assertThat(issue.confidence()).isEqualTo(AuditIssueConfidence.FIRM);
        assertThat(issue.detail()).contains("CVE-2025-53110");
    }

    @Test
    void rootDerivedFromInjectedInventoryWhenResourcesListEmpty() {
        ScanInventory inventory = new ScanInventory(List.of(), List.of(
                new McpResourceDefinition("file:///workspace/readme.txt", "readme", null, "text/plain")),
                List.of(), List.of());
        check = new McpActiveResourcePathTraversalCheck(settings, null, () -> inventory);
        stubMcpBaselineRequest();
        stubServer(body -> {
            if (isResourcesList(body)) {
                return successBody(EMPTY_RESOURCES_RESPONSE);
            }
            if (isTemplatesList(body)) {
                return successBody(EMPTY_TEMPLATES_RESPONSE);
            }
            if (body.contains("file:///workspace/" + DEEP_PLAIN_ESCAPE + "etc/passwd")) {
                return successBody(contentsBody(PASSWD_FILE_CONTENT));
            }
            return successBody(INVALID_URI_ERROR_BODY);
        });

        AuditResult result = check.doCheck(baseRequestResponse, insertionPoint, http);

        assertThat(issueNamed(result, "MCP Resource Path Traversal").severity())
                .isEqualTo(AuditIssueSeverity.HIGH);
    }

    @Test
    void templateInjectionFiresEncodingBypassWhenPlainRejected() {
        stubMcpBaselineRequest();
        String templateListResponse =
                "{\"jsonrpc\":\"2.0\",\"result\":{\"resourceTemplates\":[{\"uriTemplate\":\"file:///{path}\"}]}}";
        stubServer(body -> {
            if (isResourcesList(body)) {
                return successBody(EMPTY_RESOURCES_RESPONSE);
            }
            if (isTemplatesList(body)) {
                return successBody(templateListResponse);
            }
            if (body.contains("file:///" + DEEP_PCT_SLASH_ESCAPE + "etc%2fpasswd")) {
                return successBody(contentsBody(PASSWD_FILE_CONTENT));
            }
            return successBody(INVALID_URI_ERROR_BODY);
        });

        AuditResult result = check.doCheck(baseRequestResponse, insertionPoint, http);

        assertThat(issueNamed(result, "MCP Resource Path Traversal (Encoding Bypass)").confidence())
                .isEqualTo(AuditIssueConfidence.CERTAIN);
    }

    // -------- FP-resistance / negative controls --------

    @Test
    void safeContainedServerFiresNothing() {
        stubMcpBaselineRequest();
        stubServer(body -> {
            if (isResourcesList(body)) {
                return successBody(resourcesListWith("file:///workspace/readme.txt"));
            }
            if (isTemplatesList(body)) {
                return successBody(EMPTY_TEMPLATES_RESPONSE);
            }
            // Every probe rejected (resolve + is_relative_to containment).
            return successBody(INVALID_URI_ERROR_BODY);
        });

        AuditResult result = check.doCheck(baseRequestResponse, insertionPoint, http);

        assertThat(result.auditIssues()).isEmpty();
    }

    @Test
    void symlinkShapeNotRemotelyReachableFiresNothing() {
        // The only escape is via an on-disk symlink the scanner cannot request over JSON-RPC:
        // every URI it can send (absolute, ../, encoded, sibling) is rejected.
        stubMcpBaselineRequest();
        stubServer(body -> {
            if (isResourcesList(body)) {
                return successBody(resourcesListWith("file:///workspace/readme.txt"));
            }
            if (isTemplatesList(body)) {
                return successBody(EMPTY_TEMPLATES_RESPONSE);
            }
            // A pre-planted symlink would escape, but no URI the scanner sends matches it.
            if (body.contains("file:///workspace/link-to-secret")) {
                return successBody(contentsBody(PASSWD_FILE_CONTENT));
            }
            return successBody(INVALID_URI_ERROR_BODY);
        });

        AuditResult result = check.doCheck(baseRequestResponse, insertionPoint, http);

        assertThat(result.auditIssues()).isEmpty();
    }

    @Test
    void doesNotFireWhenAllProbesReturnErrors() {
        stubMcpBaselineRequest();
        stubServer(body -> successBody(INVALID_URI_ERROR_BODY));

        AuditResult result = check.doCheck(baseRequestResponse, insertionPoint, http);

        assertThat(result.auditIssues()).isEmpty();
    }

    @Test
    void doesNotFireWhenResultIsErrorTrueDespiteContentSignatureSubstring() {
        stubMcpBaselineRequest();
        String toolErrorWithPasswdSubstring = "{\"jsonrpc\":\"2.0\",\"result\":{\"contents\":[{\"text\":\""
                + jsonEscape(PASSWD_FILE_CONTENT) + "\"}],\"isError\":true}}";
        stubServer(body -> {
            if (isResourcesList(body)) {
                return successBody(EMPTY_RESOURCES_RESPONSE);
            }
            if (isTemplatesList(body)) {
                return successBody(EMPTY_TEMPLATES_RESPONSE);
            }
            return successBody(toolErrorWithPasswdSubstring);
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
    void doesNotFalseFireWhenContentMentionsRootInJsonField() {
        stubMcpBaselineRequest();
        String benignContentsBody = contentsBody("Found user 'root' in directory listing");
        stubServer(body -> {
            if (isResourcesList(body)) {
                return successBody(EMPTY_RESOURCES_RESPONSE);
            }
            if (isTemplatesList(body)) {
                return successBody(EMPTY_TEMPLATES_RESPONSE);
            }
            return successBody(benignContentsBody);
        });

        AuditResult result = check.doCheck(baseRequestResponse, insertionPoint, http);

        assertThat(result.auditIssues()).isEmpty();
    }

    @Test
    void consolidatesMultipleAbsoluteHitsIntoSingleIssue() {
        stubMcpBaselineRequest();
        stubServer(body -> {
            if (isResourcesList(body)) {
                return successBody(EMPTY_RESOURCES_RESPONSE);
            }
            if (isTemplatesList(body)) {
                return successBody(EMPTY_TEMPLATES_RESPONSE);
            }
            if (body.contains("file:///etc/passwd") && !body.contains("etc%2Fpasswd")) {
                return successBody(contentsBody(PASSWD_FILE_CONTENT));
            }
            if (body.contains("file:///etc/hosts") && !body.contains("etc%2Fhosts")) {
                return successBody(contentsBody(HOSTS_FILE_CONTENT));
            }
            return successBody(INVALID_URI_ERROR_BODY);
        });

        AuditResult result = check.doCheck(baseRequestResponse, insertionPoint, http);

        AuditIssue issue = issueNamed(result, "MCP Resource Arbitrary File Read");
        assertThat(issue.requestResponses()).hasSizeGreaterThanOrEqualTo(2);
    }

    @Test
    void sendsResourcesTemplatesListDiscoveryProbe() {
        stubMcpBaselineRequest();
        List<String> bodies = stubServerCapturingBodies(body -> successBody(INVALID_URI_ERROR_BODY));

        check.doCheck(baseRequestResponse, insertionPoint, http);

        assertThat(bodies).anyMatch(body -> body.contains("\"method\":\"resources/templates/list\""));
        assertThat(bodies).anyMatch(body -> body.contains("\"method\":\"resources/list\""));
    }

    @Test
    void resourceTraversalExtractsContentsWhenResponseIsSseFramed() {
        stubMcpBaselineRequest();
        stubServer(body -> {
            if (isResourcesList(body)) {
                return successBody(EMPTY_RESOURCES_RESPONSE);
            }
            if (isTemplatesList(body)) {
                return successBody(EMPTY_TEMPLATES_RESPONSE);
            }
            if (body.contains("file:///etc/passwd") && !body.contains("etc%2Fpasswd")) {
                return sseFramedBody(contentsBody(PASSWD_FILE_CONTENT));
            }
            return successBody(INVALID_URI_ERROR_BODY);
        });

        AuditResult result = check.doCheck(baseRequestResponse, insertionPoint, http);

        assertThat(onlyIssue(result).name()).isEqualTo("MCP Resource Arbitrary File Read");
    }

    @Test
    void discoverTemplateUrisReadsSseFramedTemplatesList() {
        stubMcpBaselineRequest();
        String templateListResponse =
                "{\"jsonrpc\":\"2.0\",\"result\":{\"resourceTemplates\":[{\"uriTemplate\":\"file:///{path}\"}]}}";
        stubServer(body -> {
            if (isResourcesList(body)) {
                return successBody(EMPTY_RESOURCES_RESPONSE);
            }
            if (isTemplatesList(body)) {
                return sseFramedBody(templateListResponse);
            }
            if (body.contains("file:///" + DEEP_PLAIN_ESCAPE + "etc/passwd")) {
                return successBody(contentsBody(PASSWD_FILE_CONTENT));
            }
            return successBody(INVALID_URI_ERROR_BODY);
        });

        AuditResult result = check.doCheck(baseRequestResponse, insertionPoint, http);

        assertThat(result.auditIssues()).isNotEmpty();
    }

    // -------- harness --------

    private static Function<String, HttpRequestResponse> absoluteOnlyServer() {
        return body -> {
            if (isResourcesList(body)) {
                return successBody(EMPTY_RESOURCES_RESPONSE);
            }
            if (isTemplatesList(body)) {
                return successBody(EMPTY_TEMPLATES_RESPONSE);
            }
            // Working-as-designed file server: bare absolute reads succeed; every ../ or
            // encoded escape is rejected.
            if (body.contains("file:///etc/passwd") && !body.contains("%2") && !body.contains("..")) {
                return successBody(contentsBody(PASSWD_FILE_CONTENT));
            }
            return successBody(INVALID_URI_ERROR_BODY);
        };
    }

    private static boolean isResourcesList(String body) {
        return body.contains("\"method\":\"resources/list\"");
    }

    /**
     * Models a deeply-installed non-FastMCP root-join handler (mult-fetch): a LITERAL ../ chain is
     * joined under a project root that is many directories deep, so the escape only reaches
     * /etc/passwd once the chain is at least {@code MIN_DEEP_TRAVERSAL} levels (a shallow ../../../
     * lands inside the install tree and misses). Excess ../ are harmless — path.join clamps at root.
     */
    private static final int MIN_DEEP_TRAVERSAL = 8;

    private static boolean deepLiteralTraversalToPasswd(String body, String prefix) {
        int prefixAt = body.indexOf(prefix);
        if (prefixAt < 0 || !body.contains("etc/passwd") || body.contains("%2")) {
            return false;
        }
        String afterPrefix = body.substring(prefixAt + prefix.length());
        int dotDotSlashCount = 0;
        int cursor = 0;
        while (afterPrefix.startsWith("../", cursor)) {
            dotDotSlashCount++;
            cursor += 3;
        }
        return dotDotSlashCount >= MIN_DEEP_TRAVERSAL && afterPrefix.startsWith("etc/passwd", cursor);
    }

    private static boolean isTemplatesList(String body) {
        return body.contains("\"method\":\"resources/templates/list\"");
    }

    private static String resourcesListWith(String uri) {
        return "{\"jsonrpc\":\"2.0\",\"result\":{\"resources\":[{\"uri\":\""
                + jsonEscape(uri) + "\"}]}}";
    }

    private static AuditIssue onlyIssue(AuditResult result) {
        assertThat(result.auditIssues()).hasSize(1);
        return result.auditIssues().get(0);
    }

    private static AuditIssue issueNamed(AuditResult result, String name) {
        return result.auditIssues().stream()
                .filter(issue -> issue.name().equals(name))
                .findFirst()
                .orElseThrow(() -> new AssertionError("no issue named '" + name + "' in " + result.auditIssues()
                        .stream().map(AuditIssue::name).toList()));
    }

    private static HttpRequestResponse sseFramedBody(String jsonBody) {
        String sseBody = "event: message\ndata: " + jsonBody + "\n\n";
        HttpRequestResponse rr = mock(HttpRequestResponse.class);
        HttpResponse response = mock(HttpResponse.class);
        lenient().when(rr.response()).thenReturn(response);
        lenient().when(response.statusCode()).thenReturn((short) 200);
        lenient().when(response.bodyToString()).thenReturn(sseBody);
        lenient().when(response.headerValue("Content-Type")).thenReturn("text/event-stream");
        return rr;
    }

    private void stubMcpBaselineRequest() {
        stubMcpBaselineRequestWithBody(MCP_REQUEST_BODY);
    }

    private void stubMcpBaselineRequestWithBody(String body) {
        when(baseRequestResponse.request()).thenReturn(request);
        when(request.method()).thenReturn("POST");
        when(request.bodyToString()).thenReturn(body);
        lenient().when(request.httpService()).thenReturn(httpService);
        lenient().when(httpService.secure()).thenReturn(false);
        lenient().when(httpService.host()).thenReturn("localhost");
        lenient().when(httpService.port()).thenReturn(8080);
    }

    private void stubServer(Function<String, HttpRequestResponse> responseFn) {
        when(request.withBody(anyString())).thenAnswer(invocation -> requestWithBody(invocation.getArgument(0)));
        when(http.sendRequest(any(HttpRequest.class))).thenAnswer(invocation -> {
            HttpRequest sent = invocation.getArgument(0);
            return responseFn.apply(sent.bodyToString());
        });
    }

    private List<String> stubServerCapturingBodies(Function<String, HttpRequestResponse> responseFn) {
        List<String> captured = new ArrayList<>();
        when(request.withBody(anyString())).thenAnswer(invocation -> {
            String body = invocation.getArgument(0);
            captured.add(body);
            return requestWithBody(body);
        });
        when(http.sendRequest(any(HttpRequest.class))).thenAnswer(invocation -> {
            HttpRequest sent = invocation.getArgument(0);
            return responseFn.apply(sent.bodyToString());
        });
        return captured;
    }

    private static HttpRequest requestWithBody(String body) {
        HttpRequest mutated = mock(HttpRequest.class);
        lenient().when(mutated.bodyToString()).thenReturn(body);
        return mutated;
    }

    /** A transport-layer failure: Burp returns an HttpRequestResponse with a null response. */
    private static HttpRequestResponse transientFailure() {
        HttpRequestResponse rr = mock(HttpRequestResponse.class);
        lenient().when(rr.response()).thenReturn(null);
        return rr;
    }

    private static HttpRequestResponse successBody(String responseBody) {
        HttpRequestResponse rr = mock(HttpRequestResponse.class);
        HttpResponse response = mock(HttpResponse.class);
        lenient().when(rr.response()).thenReturn(response);
        lenient().when(response.statusCode()).thenReturn((short) 200);
        lenient().when(response.bodyToString()).thenReturn(responseBody);
        return rr;
    }

    private static String contentsBody(String text) {
        return "{\"jsonrpc\":\"2.0\",\"result\":{\"contents\":[{\"text\":\""
                + jsonEscape(text) + "\"}]}}";
    }

    private static String errorMessageBody(String message) {
        return "{\"jsonrpc\":\"2.0\",\"error\":{\"code\":-32000,\"message\":\""
                + jsonEscape(message) + "\"}}";
    }

    private static String jsonEscape(String value) {
        return value.replace("\\", "\\\\")
                .replace("\"", "\\\"")
                .replace("\n", "\\n")
                .replace("\r", "\\r");
    }
}
