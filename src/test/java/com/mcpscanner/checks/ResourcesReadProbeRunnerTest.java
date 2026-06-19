package com.mcpscanner.checks;

import burp.api.montoya.http.Http;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import com.mcpscanner.checks.ResourceTraversalPayloads.TraversalPayload;
import com.mcpscanner.checks.ResourcesReadProbeRunner.ClassifiedFinding;
import com.mcpscanner.checks.ResourcesReadProbeRunner.PrefixSiblingFinding;
import com.mcpscanner.checks.ResourcesReadProbeRunner.ProbeOutcomes;
import com.mcpscanner.checks.ResourcesReadProbeRunner.TraversalHit;
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

class ResourcesReadProbeRunnerTest {

    @BeforeAll
    static void installFactory() {
        MontoyaTestFactory.install();
    }

    private static final String KEY = "file:///workspace/|etc/passwd";
    private static final Set<FileSignature> PASSWD = Set.of(FileSignature.PASSWD);

    private static final TraversalPayload PLAIN = new TraversalPayload(
            "plain", "file:///workspace/../../../etc/passwd",
            PathTraversalTier.TRAVERSAL, KEY, PASSWD);
    private static final TraversalPayload ENCODED = new TraversalPayload(
            "encoded", "file:///workspace/..%2f..%2f..%2fetc%2fpasswd",
            PathTraversalTier.ENCODING_BYPASS, KEY, PASSWD);
    private static final TraversalPayload ABSOLUTE = new TraversalPayload(
            "absolute", "file:///etc/passwd",
            PathTraversalTier.ABSOLUTE, "absolute:file:///etc/passwd", PASSWD);

    @Test
    void plainTraversalHitClassifiesAsTraversal() {
        List<ClassifiedFinding> findings = ResourcesReadProbeRunner.classify(
                List.of(PLAIN, ENCODED), outcomes(List.of(hit(PLAIN), hit(ENCODED)), Set.of()));

        assertThat(findings).singleElement()
                .satisfies(finding -> assertThat(finding.tier()).isEqualTo(PathTraversalTier.TRAVERSAL));
    }

    @Test
    void plainDeliveredAndRejectedWithEncodedHitClassifiesAsEncodingBypass() {
        // The literal ../ reached the handler and was rejected (decode-after-check), while the
        // encoded twin succeeded — the high-confidence broken-sanitizer signal.
        List<ClassifiedFinding> findings = ResourcesReadProbeRunner.classify(
                List.of(PLAIN, ENCODED), outcomes(List.of(hit(ENCODED)), Set.of(KEY)));

        assertThat(findings).singleElement()
                .satisfies(finding -> assertThat(finding.tier())
                        .isEqualTo(PathTraversalTier.ENCODING_BYPASS));
    }

    @Test
    void encodedHitWithoutDeliveredPlainRejectionClassifiesAsTraversal() {
        // The literal ../ was never delivered to the handler (e.g. the routing layer dropped the
        // literal-slash URI), so an encoded-only hit is an ordinary traversal, NOT proof of a
        // broken sanitizer — we must not over-claim ENCODING_BYPASS.
        List<ClassifiedFinding> findings = ResourcesReadProbeRunner.classify(
                List.of(PLAIN, ENCODED), outcomes(List.of(hit(ENCODED)), Set.of()));

        assertThat(findings).singleElement()
                .satisfies(finding -> assertThat(finding.tier()).isEqualTo(PathTraversalTier.TRAVERSAL));
    }

    @Test
    void absoluteOnlyHitClassifiesAsAbsolute() {
        List<ClassifiedFinding> findings = ResourcesReadProbeRunner.classify(
                List.of(ABSOLUTE), outcomes(List.of(hit(ABSOLUTE)), Set.of()));

        assertThat(findings).singleElement()
                .satisfies(finding -> assertThat(finding.tier()).isEqualTo(PathTraversalTier.ABSOLUTE));
    }

    @Test
    void noHitsProducesNoFindings() {
        assertThat(ResourcesReadProbeRunner.classify(
                List.of(PLAIN, ENCODED), outcomes(List.of(), Set.of()))).isEmpty();
    }

    @Test
    void runAllRecordsHandlerRejectionOfPlainTraversalAsDeliveredAndRejected() {
        // The literal ../ reached the handler and was rejected there ("Invalid URI") rather than
        // missing the router — that is the sanitizer-present signal the differential needs.
        Http http = httpReturning(errorBody("Invalid URI: path traversal blocked"));

        ProbeOutcomes outcomes = new ResourcesReadProbeRunner(http).runAll(baseline(), List.of(PLAIN));

        assertThat(outcomes.hits()).isEmpty();
        assertThat(outcomes.plainDeliveredAndRejectedKeys()).containsExactly(KEY);
    }

    @Test
    void runAllIgnoresRoutingMissForPlainTraversal() {
        // "Unknown resource" means the URI never matched a handler (the routing layer dropped the
        // literal-slash URI) — not evidence of a sanitizer, so it must not count.
        Http http = httpReturning(errorBody("Unknown resource"));

        ProbeOutcomes outcomes = new ResourcesReadProbeRunner(http).runAll(baseline(), List.of(PLAIN));

        assertThat(outcomes.plainDeliveredAndRejectedKeys()).isEmpty();
    }

    @Test
    void runAllIgnoresGenericNotFoundForPlainTraversal() {
        // A plain JSON-RPC "Not found" / "does not exist" / "no such" is an ordinary routing miss,
        // not a sanitizer rejection of the delivered literal — counting it would (paired with an
        // encoded hit) over-claim ENCODING_BYPASS instead of ordinary TRAVERSAL.
        for (String message : List.of("Not found", "Resource does not exist", "no such file")) {
            Http http = httpReturning(errorBody(message));

            ProbeOutcomes outcomes = new ResourcesReadProbeRunner(http).runAll(baseline(), List.of(PLAIN));

            assertThat(outcomes.plainDeliveredAndRejectedKeys()).isEmpty();
        }
    }

    @Test
    void genericNotFoundLiteralWithEncodedHitClassifiesAsTraversal() {
        // End-to-end: the plain literal came back a generic "Not found" (routing miss, NOT a
        // delivered-and-rejected sanitizer signal) while the encoded twin succeeded -> ordinary
        // TRAVERSAL, never ENCODING_BYPASS.
        Http http = bodyAwareHttp(body -> {
            if (body.contains("%2f")) {
                return passwdContents();
            }
            return errorBody("Not found");
        });

        List<ClassifiedFinding> findings = new ResourcesReadProbeRunner(http)
                .probeAndClassify(bodyEchoBaseline(), List.of(PLAIN, ENCODED));

        assertThat(findings).singleElement()
                .satisfies(finding -> assertThat(finding.tier()).isEqualTo(PathTraversalTier.TRAVERSAL));
    }

    @Test
    void runAllIgnoresEmptyErrorMessageForPlainTraversal() {
        Http http = httpReturning(errorBody(""));

        ProbeOutcomes outcomes = new ResourcesReadProbeRunner(http).runAll(baseline(), List.of(PLAIN));

        assertThat(outcomes.plainDeliveredAndRejectedKeys()).isEmpty();
    }

    @Test
    void runAllIgnoresNonObjectErrorForPlainTraversal() {
        // A success-shaped body with no "error" object cannot be a handler rejection.
        Http http = httpReturning("{\"jsonrpc\":\"2.0\",\"result\":{\"contents\":[]}}");

        ProbeOutcomes outcomes = new ResourcesReadProbeRunner(http).runAll(baseline(), List.of(PLAIN));

        assertThat(outcomes.plainDeliveredAndRejectedKeys()).isEmpty();
    }

    // -------- template discovery: embedded resourceTemplates in resources/list --------

    @Test
    void discoverTemplateUrisReadsEmbeddedTemplatesFromResourcesListResponse() {
        // Some plain MCP SDK servers (not FastMCP) advertise resourceTemplates INSIDE the
        // resources/list response and registers NO resources/templates/list handler (it returns
        // -32601). The runner must still surface the file:///src/{path} template so the check can
        // probe it — otherwise the genuine arbitrary-file-read is a false negative.
        Http http = bodyAwareHttp(body -> {
            if (body.contains("resources/templates/list")) {
                return "{\"jsonrpc\":\"2.0\",\"error\":{\"code\":-32601,\"message\":\"Method not found\"}}";
            }
            if (body.contains("resources/list")) {
                return "{\"jsonrpc\":\"2.0\",\"result\":{\"resources\":[{\"uri\":\"file:///logs/debug\"}],"
                        + "\"resourceTemplates\":[{\"uriTemplate\":\"file:///src/{path}\"},"
                        + "{\"uriTemplate\":\"file:///docs/{path}\"}]}}";
            }
            return errorBody("Invalid URI");
        });

        List<String> templates = new ResourcesReadProbeRunner(http).discoverTemplateUris(bodyEchoBaseline());

        assertThat(templates).contains("file:///src/{path}", "file:///docs/{path}");
    }

    @Test
    void discoverTemplateUrisStillReadsDedicatedTemplatesListMethod() {
        // A spec-compliant server that DOES implement resources/templates/list keeps working.
        Http http = bodyAwareHttp(body -> {
            if (body.contains("resources/templates/list")) {
                return "{\"jsonrpc\":\"2.0\",\"result\":{\"resourceTemplates\":"
                        + "[{\"uriTemplate\":\"rooted:///{path}\"}]}}";
            }
            return "{\"jsonrpc\":\"2.0\",\"result\":{\"resources\":[]}}";
        });

        List<String> templates = new ResourcesReadProbeRunner(http).discoverTemplateUris(bodyEchoBaseline());

        assertThat(templates).contains("rooted:///{path}");
    }

    // -------- prefix-sibling error-differential oracle (shared with the tool runner) --------

    @Test
    void prefixSiblingNotFoundWithDeniedControlFires() {
        // The deny-control (non-prefix out-of-root URI) is access-denied AND the prefix-sharing
        // sibling returns a filesystem not-found -> the shared oracle confirms the bypass.
        Http http = bodyAwareHttp(body -> {
            if (body.contains("mcpscan-nonexistent")) {
                return errorBody("path is outside the resource root");
            }
            return errorBody("[Errno 2] No such file or directory: '/srv/ws_mcpscan_x/y'");
        });

        List<PrefixSiblingFinding> findings = new ResourcesReadProbeRunner(http)
                .probePrefixSibling(bodyEchoBaseline(), List.of("prefixmatch:///srv/ws/canary.txt"));

        // The single stripped-parent probe carries the genuinely out-of-root sibling (..%2fws_mcpscan_)
        // — the relevant one for this file-rooted URI — and fires on the not-found-vs-denied differential.
        assertThat(findings).isNotEmpty()
                .anySatisfy(f -> assertThat(f.probedUri()).contains("ws_mcpscan_"));
    }

    @Test
    void prefixSiblingDeniedSiblingDoesNotFire() {
        // A correctly-bounded handler denies the sibling too (containment held) -> no false positive.
        Http http = bodyAwareHttp(body -> errorBody("path is outside the resource root"));

        List<PrefixSiblingFinding> findings = new ResourcesReadProbeRunner(http)
                .probePrefixSibling(bodyEchoBaseline(), List.of("prefixmatch:///srv/ws/canary.txt"));

        assertThat(findings).isEmpty();
    }

    @Test
    void prefixSiblingNotFoundMaskingServerIsSkippedWhenControlNotDenied() {
        // Both the deny-control and the sibling come back not-found -> the oracle is blind -> SKIP.
        Http http = bodyAwareHttp(body -> errorBody("[Errno 2] No such file or directory"));

        List<PrefixSiblingFinding> findings = new ResourcesReadProbeRunner(http)
                .probePrefixSibling(bodyEchoBaseline(), List.of("prefixmatch:///srv/ws/canary.txt"));

        assertThat(findings).isEmpty();
    }

    @Test
    void boundedFileResourceDoesNotFirePrefixSibling() {
        // Regression (Codex review): a CORRECTLY-bounded server that lists a FILE resource must NOT
        // produce a prefix-sibling finding. The dropped verbatim probe used to build a "sibling"
        // (readme.txt_mcpscan_<rnd>/...) that resolves INSIDE the root, so a bounded server answered
        // it not-found (in-root, missing) while the out-of-root deny-control was denied — satisfying
        // the oracle WITHOUT any real CVE-2025-53110 bug. With the verbatim prefix-sibling probe gone,
        // only the stripped-parent probe runs: its sibling is genuinely out-of-root (..%2f<root>_mcpscan)
        // and a bounded server denies it, so nothing fires.
        Http http = bodyAwareHttp(body -> {
            if (body.contains("mcpscan-nonexistent")) {
                return errorBody("path is outside the resource root");
            }
            if (body.contains("readme.txt_mcpscan_")) {
                // The verbatim "sibling" resolves in-root -> a bounded server returns not-found here.
                return errorBody("[Errno 2] No such file or directory");
            }
            // The stripped-parent sibling (..%2fworkspace_mcpscan_) is genuinely out-of-root: denied.
            return errorBody("path is outside the resource root");
        });

        List<PrefixSiblingFinding> findings = new ResourcesReadProbeRunner(http)
                .probePrefixSibling(bodyEchoBaseline(), List.of("file:///workspace/readme.txt"));

        assertThat(findings).isEmpty();
    }

    @Test
    void prefixSiblingSkippedForResourceWithNoDerivableRoot() {
        // docs://readme has no file-rooted authority shape -> no probe pair -> the tier is skipped.
        Http http = bodyAwareHttp(body -> errorBody("path is outside the resource root"));

        List<PrefixSiblingFinding> findings = new ResourcesReadProbeRunner(http)
                .probePrefixSibling(bodyEchoBaseline(), List.of("docs://readme"));

        assertThat(findings).isEmpty();
    }

    private static ProbeOutcomes outcomes(List<TraversalHit> hits, Set<String> deliveredRejected) {
        return new ProbeOutcomes(hits, deliveredRejected);
    }

    private static HttpRequest bodyEchoBaseline() {
        HttpRequest baseline = mock(HttpRequest.class);
        lenient().when(baseline.withBody(anyString())).thenAnswer(invocation -> {
            HttpRequest withBody = mock(HttpRequest.class);
            String body = invocation.getArgument(0);
            lenient().when(withBody.bodyToString()).thenReturn(body);
            return withBody;
        });
        return baseline;
    }

    private static Http bodyAwareHttp(java.util.function.Function<String, String> responseForBody) {
        Http http = mock(Http.class);
        when(http.sendRequest(any(HttpRequest.class))).thenAnswer(invocation -> {
            String body = ((HttpRequest) invocation.getArgument(0)).bodyToString();
            return responseFor(responseForBody.apply(body == null ? "" : body));
        });
        return http;
    }

    private static TraversalHit hit(TraversalPayload payload) {
        return new TraversalHit(payload, mock(HttpRequestResponse.class));
    }

    private static HttpRequest baseline() {
        HttpRequest baseline = mock(HttpRequest.class);
        lenient().when(baseline.withBody(anyString())).thenReturn(mock(HttpRequest.class));
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
        return rr;
    }

    private static String passwdContents() {
        // A resources/read success envelope whose single content carries a coherent passwd body
        // (root + 2 distinct users) so PASSWD's FileSignature fires.
        return "{\"jsonrpc\":\"2.0\",\"result\":{\"contents\":[{\"text\":\""
                + "root:x:0:0:root:/root:/bin/bash\\n"
                + "daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\\n"
                + "bin:x:2:2:bin:/bin:/usr/sbin/nologin\\n\"}]}}";
    }

    private static String errorBody(String message) {
        return "{\"jsonrpc\":\"2.0\",\"error\":{\"code\":-32000,\"message\":\""
                + message.replace("\"", "\\\"") + "\"}}";
    }
}
