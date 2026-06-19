package com.mcpscanner.checks;

import burp.api.montoya.http.Http;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import com.mcpscanner.checks.ToolArgTraversalPayloads.ToolArgPayload;
import com.mcpscanner.checks.ToolsCallTraversalProbeRunner.ClassifiedFinding;
import com.mcpscanner.checks.ToolsCallTraversalProbeRunner.PrefixSiblingFinding;
import com.mcpscanner.checks.ToolsCallTraversalProbeRunner.ProbeOutcomes;
import com.mcpscanner.checks.ToolsCallTraversalProbeRunner.TraversalHit;
import com.mcpscanner.checks.ToolsListDiscovery.DiscoveredTool;
import com.mcpscanner.mcp.McpObjectMapper;
import com.mcpscanner.testutil.MontoyaTestFactory;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class ToolsCallTraversalProbeRunnerTest {

    @BeforeAll
    static void installFactory() {
        MontoyaTestFactory.install();
    }

    private static final String READ_FILE_SCHEMA =
            "{\"type\":\"object\",\"properties\":{\"path\":{\"type\":\"string\"}},\"required\":[\"path\"]}";

    private static final DiscoveredTool READ_FILE = discoveredTool("read_file", READ_FILE_SCHEMA);
    private static final ToolArgument PATH_ARG = new ToolArgument(READ_FILE, "path");

    private static final String KEY = "traversal:etc/passwd";
    private static final Set<FileSignature> PASSWD = Set.of(FileSignature.PASSWD);

    private static final ToolArgPayload PLAIN = new ToolArgPayload(
            "plain", "../../../etc/passwd", PathTraversalTier.TRAVERSAL, KEY, PASSWD);
    private static final ToolArgPayload ENCODED = new ToolArgPayload(
            "encoded", "..%2f..%2f..%2fetc%2fpasswd", PathTraversalTier.ENCODING_BYPASS, KEY, PASSWD);
    private static final ToolArgPayload ABSOLUTE = new ToolArgPayload(
            "absolute", "/etc/passwd", PathTraversalTier.ABSOLUTE, "absolute:/etc/passwd", PASSWD);

    // -------- classifier (mirrors ResourcesReadProbeRunnerTest) --------

    @Test
    void plainTraversalHitClassifiesAsTraversal() {
        List<ClassifiedFinding> findings = ToolsCallTraversalProbeRunner.classify(
                PATH_ARG, outcomes(List.of(hit(PLAIN), hit(ENCODED)), Set.of()));

        assertThat(findings).singleElement()
                .satisfies(f -> assertThat(f.tier()).isEqualTo(PathTraversalTier.TRAVERSAL));
    }

    @Test
    void plainDeliveredAndRejectedWithEncodedHitClassifiesAsEncodingBypass() {
        List<ClassifiedFinding> findings = ToolsCallTraversalProbeRunner.classify(
                PATH_ARG, outcomes(List.of(hit(ENCODED)), Set.of(KEY)));

        assertThat(findings).singleElement()
                .satisfies(f -> assertThat(f.tier()).isEqualTo(PathTraversalTier.ENCODING_BYPASS));
    }

    @Test
    void encodedHitWithoutDeliveredPlainRejectionClassifiesAsTraversal() {
        // No positive evidence the literal ../ reached the handler — do not over-claim a broken
        // sanitizer.
        List<ClassifiedFinding> findings = ToolsCallTraversalProbeRunner.classify(
                PATH_ARG, outcomes(List.of(hit(ENCODED)), Set.of()));

        assertThat(findings).singleElement()
                .satisfies(f -> assertThat(f.tier()).isEqualTo(PathTraversalTier.TRAVERSAL));
    }

    @Test
    void absoluteOnlyHitClassifiesAsAbsolute() {
        List<ClassifiedFinding> findings = ToolsCallTraversalProbeRunner.classify(
                PATH_ARG, outcomes(List.of(hit(ABSOLUTE)), Set.of()));

        assertThat(findings).singleElement()
                .satisfies(f -> assertThat(f.tier()).isEqualTo(PathTraversalTier.ABSOLUTE));
    }

    @Test
    void noHitsProducesNoFindings() {
        assertThat(ToolsCallTraversalProbeRunner.classify(
                PATH_ARG, outcomes(List.of(), Set.of()))).isEmpty();
    }

    // -------- runArgument: delivered-and-rejected evidence gate --------

    @Test
    void runArgumentRecordsToolErrorRejectionOfPlainTraversalAsDeliveredAndRejected() {
        // A tools/call tool-error envelope (isError=true, recognised method) for the literal ../
        // means the handler ran and rejected the input — the sanitizer-present signal.
        Http http = httpReturning(toolError("path traversal blocked"));

        ProbeOutcomes outcomes = new ToolsCallTraversalProbeRunner(http)
                .runArgument(baseline(), PATH_ARG, List.of(PLAIN));

        assertThat(outcomes.hits()).isEmpty();
        assertThat(outcomes.plainDeliveredAndRejectedKeys()).containsExactly(KEY);
    }

    @Test
    void runArgumentIgnoresMethodNotFoundForPlainTraversal() {
        // -32601 means the tool was never dispatched (routing miss) — not a sanitizer signal.
        Http http = httpReturning(
                "{\"jsonrpc\":\"2.0\",\"error\":{\"code\":-32601,\"message\":\"Method not found\"}}");

        ProbeOutcomes outcomes = new ToolsCallTraversalProbeRunner(http)
                .runArgument(baseline(), PATH_ARG, List.of(PLAIN));

        assertThat(outcomes.plainDeliveredAndRejectedKeys()).isEmpty();
    }

    @Test
    void runArgumentIgnoresSuccessfulReadForPlainTraversal() {
        // A success that did not match the signature is not a handler rejection.
        Http http = httpReturning(
                "{\"jsonrpc\":\"2.0\",\"result\":{\"content\":[{\"type\":\"text\",\"text\":\"hi\"}]}}");

        ProbeOutcomes outcomes = new ToolsCallTraversalProbeRunner(http)
                .runArgument(baseline(), PATH_ARG, List.of(PLAIN));

        assertThat(outcomes.plainDeliveredAndRejectedKeys()).isEmpty();
    }

    // -------- prefix-sibling not-found-vs-denied differential + root derivation --------

    @Test
    void prefixSiblingNotFoundWithDeniedControlFires() {
        // Root derived from a list_allowed_directories tool. The deny-control (a non-prefix
        // out-of-root path) is access-denied AND the prefix-sharing sibling returns a filesystem
        // not-found -> the oracle confirms the naive prefix-match bypass.
        DiscoveredTool listDirs = discoveredTool("list_allowed_directories", "{\"type\":\"object\"}");
        Http http = mock(Http.class);
        HttpRequest baseline = baseline();
        when(http.sendRequest(any(HttpRequest.class))).thenAnswer(invocation -> {
            String body = ((HttpRequest) invocation.getArgument(0)).bodyToString();
            if (body.contains("list_allowed_directories")) {
                return responseFor(toolError("Allowed directories:\n/srv/workspace"));
            }
            if (body.contains("mcpscan-nonexistent")) {
                return responseFor(toolError(
                        "Access denied - path outside allowed directories: <ctrl> not in /srv/workspace"));
            }
            return responseFor(toolError(
                    "Error: Parent directory does not exist: /srv/workspace_mcpscan_ab"));
        });

        List<PrefixSiblingFinding> findings = new ToolsCallTraversalProbeRunner(http)
                .probePrefixSibling(baseline, List.of(READ_FILE, listDirs), List.of(PATH_ARG));

        assertThat(findings).singleElement()
                .satisfies(f -> assertThat(f.argument()).isEqualTo(PATH_ARG));
    }

    @Test
    void prefixSiblingAccessDeniedForOutOfRootPathDoesNotFire() {
        // A correctly-bounded server denies the out-of-root sibling before touching the filesystem
        // (negative control) -> no false positive.
        DiscoveredTool listDirs = discoveredTool("list_allowed_directories", "{\"type\":\"object\"}");
        Http http = mock(Http.class);
        when(http.sendRequest(any(HttpRequest.class))).thenAnswer(invocation -> {
            String body = ((HttpRequest) invocation.getArgument(0)).bodyToString();
            if (body.contains("list_allowed_directories")) {
                return responseFor(toolError("Allowed directories:\n/srv/workspace"));
            }
            return responseFor(toolError(
                    "Access denied - path outside allowed directories: "
                            + "/srv/workspace_mcpscan_ab/zz not in /srv/workspace"));
        });

        List<PrefixSiblingFinding> findings = new ToolsCallTraversalProbeRunner(http)
                .probePrefixSibling(baseline(), List.of(READ_FILE, listDirs), List.of(PATH_ARG));

        assertThat(findings).isEmpty();
    }

    @Test
    void prefixSiblingNotFoundMaskingServerIsSkippedWhenControlNotDenied() {
        // A server that maps EVERY rejected path to a "file not found" (the deny-control is itself
        // not-found, not access-denied) makes the oracle blind -> SKIP, no false positive. The root
        // still leaks via the discovery tool so we reach the control check.
        DiscoveredTool listDirs = discoveredTool("list_allowed_directories", "{\"type\":\"object\"}");
        Http http = mock(Http.class);
        when(http.sendRequest(any(HttpRequest.class))).thenAnswer(invocation -> {
            String body = ((HttpRequest) invocation.getArgument(0)).bodyToString();
            if (body.contains("list_allowed_directories")) {
                return responseFor(toolError("Allowed directories:\n/srv/workspace"));
            }
            // Both the deny-control and the sibling come back not-found -> oracle is blind.
            return responseFor(toolError("ENOENT: no such file or directory"));
        });

        List<PrefixSiblingFinding> findings = new ToolsCallTraversalProbeRunner(http)
                .probePrefixSibling(baseline(), List.of(READ_FILE, listDirs), List.of(PATH_ARG));

        assertThat(findings).isEmpty();
    }

    @Test
    void prefixSiblingDerivesRootFromRejectionWhenNoDiscoveryTool() {
        // No list-allowed-directories tool: the deny-control probe provokes a root-naming rejection
        // (which both derives the root AND serves as the access-denied control), then the
        // prefix-sharing sibling returns not-found -> a finding.
        Http http = mock(Http.class);
        when(http.sendRequest(any(HttpRequest.class))).thenAnswer(invocation -> {
            String body = ((HttpRequest) invocation.getArgument(0)).bodyToString();
            if (body.contains("mcpscan-nonexistent")) {
                return responseFor(toolError(
                        "Access denied - path outside allowed directories: "
                                + "/mcpscan-nonexistent__mcpscan_root not in /data/root"));
            }
            // The follow-up sibling probe (sharing the /data/root prefix) returns not-found.
            return responseFor(toolError("ENOENT: no such file or directory, open '/data/root_mcpscan_x'"));
        });

        List<PrefixSiblingFinding> findings = new ToolsCallTraversalProbeRunner(http)
                .probePrefixSibling(baseline(), List.of(READ_FILE), List.of(PATH_ARG));

        assertThat(findings).hasSize(1);
    }

    @Test
    void prefixSiblingSkippedWhenNoRootCanBeDerived() {
        // No discovery tool and no leaked root -> the tier is skipped entirely (no FP).
        Http http = httpReturning(toolError("could not read file"));

        List<PrefixSiblingFinding> findings = new ToolsCallTraversalProbeRunner(http)
                .probePrefixSibling(baseline(), List.of(READ_FILE), List.of(PATH_ARG));

        assertThat(findings).isEmpty();
    }

    // -------- helpers --------

    private static ProbeOutcomes outcomes(List<TraversalHit> hits, Set<String> deliveredRejected) {
        return new ProbeOutcomes(hits, deliveredRejected);
    }

    private static TraversalHit hit(ToolArgPayload payload) {
        return new TraversalHit(PATH_ARG, payload, mock(HttpRequestResponse.class));
    }

    private static DiscoveredTool discoveredTool(String name, String schemaJson) {
        try {
            return new DiscoveredTool(name, McpObjectMapper.INSTANCE.readTree(schemaJson));
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }

    private static HttpRequest baseline() {
        HttpRequest baseline = mock(HttpRequest.class);
        lenient().when(baseline.withBody(anyString())).thenAnswer(invocation -> {
            HttpRequest withBody = mock(HttpRequest.class);
            String body = invocation.getArgument(0);
            lenient().when(withBody.bodyToString()).thenReturn(body);
            return withBody;
        });
        return baseline;
    }

    private static Http httpReturning(String responseBody) {
        HttpRequestResponse response = responseFor(responseBody);
        Http http = mock(Http.class);
        when(http.sendRequest(any(HttpRequest.class))).thenReturn(response);
        return http;
    }

    private static HttpRequestResponse responseFor(String responseBody) {
        HttpRequestResponse rr = mock(HttpRequestResponse.class);
        HttpResponse response = mock(HttpResponse.class);
        lenient().when(rr.response()).thenReturn(response);
        lenient().when(response.statusCode()).thenReturn((short) 200);
        lenient().when(response.bodyToString()).thenReturn(responseBody);
        lenient().when(response.headerValue("Content-Type")).thenReturn("application/json");
        return rr;
    }

    private static String toolError(String message) {
        return "{\"jsonrpc\":\"2.0\",\"result\":{\"isError\":true,\"content\":[{\"type\":\"text\",\"text\":\""
                + message.replace("\\", "\\\\").replace("\"", "\\\"").replace("\n", "\\n") + "\"}]}}";
    }
}
