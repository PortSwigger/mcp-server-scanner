package com.mcpscanner.checks;

import burp.api.montoya.http.Http;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import com.fasterxml.jackson.databind.JsonNode;
import com.mcpscanner.checks.ResourceTraversalPayloads.TraversalPayload;
import com.mcpscanner.mcp.JsonRpcBody;
import com.mcpscanner.mcp.McpObjectMapper;
import com.mcpscanner.mcp.McpRequestDetector;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

public final class ResourcesReadProbeRunner {

    public record TraversalHit(TraversalPayload payload, HttpRequestResponse response) {}

    public record ClassifiedFinding(PathTraversalTier tier, String differentialKey,
                                    List<TraversalHit> evidence) {}

    /** A confirmed CVE-2025-53110 root-boundary bypass on resources/read: a non-existent
     *  prefix-sharing sibling returned a filesystem not-found while the deny-control (a non-prefix
     *  out-of-root URI) was access-denied — proving naive prefix-match containment, no planted file. */
    public record PrefixSiblingFinding(String probedUri, HttpRequestResponse response) {}

    private static final String READ_METHOD = "resources/read";
    private static final String TEMPLATES_LIST_METHOD = "resources/templates/list";
    private static final String RESOURCES_LIST_METHOD = "resources/list";

    private final Http http;

    public ResourcesReadProbeRunner(Http http) {
        this.http = http;
    }

    public List<String> discoverTemplateUris(HttpRequest baseline) {
        // Templates are advertised two ways in the wild: the dedicated resources/templates/list
        // method (spec-compliant FastMCP) AND embedded as a resourceTemplates array on the
        // resources/list response (some plain MCP SDK servers, which
        // register no templates/list handler and return -32601 for it). Reading only the dedicated
        // method silently misses the embedded form, leaving a genuinely vulnerable template
        // unprobed. We read both and merge, deduping by URI template. Discovery broadening only —
        // every probe built from these templates is still gated by the FileSignature oracle.
        LinkedHashSet<String> templates = new LinkedHashSet<>(
                discoverUris(baseline, TEMPLATES_LIST_METHOD, "resourceTemplates", "uriTemplate"));
        templates.addAll(discoverUris(baseline, RESOURCES_LIST_METHOD, "resourceTemplates", "uriTemplate"));
        return new ArrayList<>(templates);
    }

    public List<String> discoverResourceUris(HttpRequest baseline) {
        return discoverUris(baseline, RESOURCES_LIST_METHOD, "resources", "uri");
    }

    private List<String> discoverUris(HttpRequest baseline, String method,
                                      String arrayField, String uriField) {
        HttpRequestResponse response = http.sendRequest(
                baseline.withBody(JsonRpcBody.emptyParams(method)));
        if (!McpRequestDetector.isNonErrorMcpResponse(response)) {
            return List.of();
        }
        String body = McpRequestDetector.jsonRpcBody(response.response());
        if (body == null || body.isEmpty()) {
            return List.of();
        }
        try {
            JsonNode entries = McpObjectMapper.INSTANCE.readTree(body).path("result").path(arrayField);
            if (!entries.isArray()) {
                return List.of();
            }
            List<String> uris = new ArrayList<>();
            for (JsonNode entry : entries) {
                JsonNode uri = entry.path(uriField);
                if (uri.isTextual()) {
                    uris.add(uri.asText());
                }
            }
            return uris;
        } catch (Exception ignored) {
            return List.of();
        }
    }

    /** Per-payload run outcome the classifier needs: a signature hit, and — for plain
     *  traversal payloads — whether the server actually <em>delivered</em> the literal {@code ../}
     *  to the resource handler (vs rejecting it at the routing layer before the handler ran). */
    record ProbeOutcomes(List<TraversalHit> hits, Set<String> plainDeliveredAndRejectedKeys) {}

    public List<ClassifiedFinding> probeAndClassify(HttpRequest baseline, List<TraversalPayload> payloads) {
        return classify(payloads, runAll(baseline, payloads));
    }

    /**
     * Probes each discovered file-rooted resource URI for a naive-prefix-match root boundary
     * (CVE-2025-53110) WITHOUT reading any out-of-root secret, using the SAME error-differential
     * oracle as the tool path ({@link FilesystemErrorOracle}). For each derivable root it sends a
     * DENY-CONTROL (clearly out-of-root, non-prefix-sharing) once and a NON-EXISTENT prefix-sharing
     * sibling; a finding fires only when the control was distinguishably access-denied AND the
     * sibling was a filesystem not-found. A not-found-masking server fails the control and is
     * skipped; a correctly-bounded server denies the sibling and produces no finding.
     */
    public List<PrefixSiblingFinding> probePrefixSibling(HttpRequest baseline,
                                                         List<String> resourceUris) {
        List<PrefixSiblingFinding> findings = new ArrayList<>();
        for (String resourceUri : resourceUris) {
            // The stripped-parent probe builds a sibling that is genuinely OUT-OF-ROOT
            // (..%2f<root>_mcpscan_<rnd>) — a bounded server denies it, so it fires only on the
            // not-found-vs-denied differential. A verbatim-base probe was deliberately dropped: for a
            // FILE resource its "sibling" (<root>_mcpscan_<rnd>) resolves INSIDE the root, which a
            // bounded server answers not-found, falsely satisfying the oracle (a MEDIUM/FIRM FP). The
            // real DiggAI directory-root server is still caught by the verbatim CONTENT traversal
            // probes (FileSignature-gated), not by a prefix-sibling probe.
            addPrefixSiblingFinding(baseline, findings,
                    ResourceTraversalPayloads.prefixSiblingProbe(resourceUri));
        }
        return findings;
    }

    private void addPrefixSiblingFinding(HttpRequest baseline, List<PrefixSiblingFinding> findings,
                                         ResourceTraversalPayloads.PrefixSiblingProbe probe) {
        if (probe == null) {
            return;
        }
        HttpRequestResponse denyControl = sendRead(baseline, probe.denyControlUri());
        HttpRequestResponse sibling = sendRead(baseline, probe.siblingUri());
        if (FilesystemErrorOracle.prefixSiblingConfirmed(denyControl, sibling)) {
            findings.add(new PrefixSiblingFinding(probe.siblingUri(), sibling));
        }
    }

    private HttpRequestResponse sendRead(HttpRequest baseline, String uri) {
        return http.sendRequest(baseline.withBody(JsonRpcBody.singleStringParam(READ_METHOD, "uri", uri)));
    }

    ProbeOutcomes runAll(HttpRequest baseline, List<TraversalPayload> payloads) {
        List<TraversalHit> hits = new ArrayList<>();
        Set<String> plainDeliveredAndRejected = new HashSet<>();
        for (TraversalPayload payload : payloads) {
            HttpRequestResponse response = http.sendRequest(
                    baseline.withBody(JsonRpcBody.singleStringParam(READ_METHOD, "uri", payload.uri())));
            if (responseMatchesExpectedSignature(response, payload.expectedSignatures())) {
                hits.add(new TraversalHit(payload, response));
            } else if (payload.tier() == PathTraversalTier.TRAVERSAL
                    && literalPathDeliveredToHandler(response)) {
                // The literal ../ reached the handler and was rejected there — positive evidence
                // a sanitizer is present. Paired with an encoded twin hit this is the
                // decode-after-check ENCODING_BYPASS signal.
                plainDeliveredAndRejected.add(payload.differentialKey());
            }
        }
        return new ProbeOutcomes(hits, plainDeliveredAndRejected);
    }

    static List<ClassifiedFinding> classify(List<TraversalPayload> sent, ProbeOutcomes outcomes) {
        Map<String, List<TraversalHit>> hitsByKey = new LinkedHashMap<>();
        for (TraversalHit hit : outcomes.hits()) {
            hitsByKey.computeIfAbsent(hit.payload().differentialKey(), ignored -> new ArrayList<>())
                    .add(hit);
        }
        List<ClassifiedFinding> findings = new ArrayList<>();
        for (Map.Entry<String, List<TraversalHit>> entry : hitsByKey.entrySet()) {
            PathTraversalTier tier = resolveTier(entry.getValue(),
                    outcomes.plainDeliveredAndRejectedKeys().contains(entry.getKey()));
            findings.add(new ClassifiedFinding(tier, entry.getKey(), entry.getValue()));
        }
        return findings;
    }

    private static PathTraversalTier resolveTier(List<TraversalHit> groupedHits,
                                                 boolean plainDeliveredAndRejected) {
        return TraversalTierClassifier.resolve(
                groupedHits.stream().map(hit -> hit.payload().tier()).toList(),
                plainDeliveredAndRejected);
    }

    private static boolean literalPathDeliveredToHandler(HttpRequestResponse response) {
        // Guard a transport failure on the plain probe (mirrors the tool runner): a null/non-200
        // response is "no evidence", not a delivered-and-rejected signal — keep the gate closed.
        if (response.response() == null || response.response().statusCode() != 200) {
            return false;
        }
        String body = McpRequestDetector.jsonRpcBody(response.response());
        if (body == null || body.isEmpty()) {
            return false;
        }
        try {
            JsonNode error = McpObjectMapper.INSTANCE.readTree(body).path("error");
            if (!error.isObject()) {
                return false;
            }
            String message = error.path("message").asText("");
            // A not-found / unknown-resource error means the URI never matched a handler (routing-
            // layer reject, literal slashes dropped) — NOT a sanitizer rejection. Generic not-found
            // phrasings ("Not found", "does not exist", "no such ...") must be excluded too, else an
            // ordinary routing miss is mistaken for a delivered-and-rejected literal and (paired with
            // an encoded hit) over-claims ENCODING_BYPASS. Any OTHER non-empty error means the
            // handler ran and rejected the input — the sanitizer we are differentially probing for.
            String lower = message.toLowerCase();
            return !lower.isEmpty() && !isRoutingMiss(lower);
        } catch (Exception ignored) {
            return false;
        }
    }

    private static boolean isRoutingMiss(String lowerMessage) {
        return lowerMessage.contains("unknown resource")
                || lowerMessage.contains("resource not found")
                || lowerMessage.contains("not found")
                || lowerMessage.contains("does not exist")
                || lowerMessage.contains("no such");
    }

    private static boolean responseMatchesExpectedSignature(HttpRequestResponse response,
                                                            Set<FileSignature> expectedSignatures) {
        if (!McpRequestDetector.isToolCallSuccess(response)) {
            return false;
        }
        String body = McpRequestDetector.jsonRpcBody(response.response());
        if (body == null || body.isEmpty()) {
            return false;
        }
        for (String text : extractContentsText(body)) {
            for (FileSignature signature : expectedSignatures) {
                if (signature.matches(text)) {
                    return true;
                }
            }
        }
        return false;
    }

    private static List<String> extractContentsText(String body) {
        try {
            JsonNode contents = McpObjectMapper.INSTANCE.readTree(body).path("result").path("contents");
            if (!contents.isArray()) {
                return List.of();
            }
            List<String> texts = new ArrayList<>(contents.size());
            for (JsonNode entry : contents) {
                JsonNode text = entry.path("text");
                if (text.isTextual()) {
                    texts.add(text.asText());
                }
            }
            return texts;
        } catch (Exception ignored) {
            return List.of();
        }
    }
}
