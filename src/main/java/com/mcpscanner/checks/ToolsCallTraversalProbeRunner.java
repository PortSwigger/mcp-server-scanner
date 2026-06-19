package com.mcpscanner.checks;

import burp.api.montoya.http.Http;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import com.fasterxml.jackson.databind.JsonNode;
import com.mcpscanner.checks.ToolArgTraversalPayloads.ToolArgPayload;
import com.mcpscanner.checks.ToolsListDiscovery.DiscoveredTool;
import com.mcpscanner.mcp.McpObjectMapper;
import com.mcpscanner.mcp.McpRequestDetector;
import com.mcpscanner.scan.PathArgumentHeuristic;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

public final class ToolsCallTraversalProbeRunner {

    public record TraversalHit(ToolArgument argument, ToolArgPayload payload, HttpRequestResponse response) {}

    /** A confirmed CVE-2025-53110 root-boundary bypass: the server returned a filesystem
     *  not-found error (not an access-denied) for a non-existent path that lies OUTSIDE the
     *  allowed root but shares its string prefix — proving naive prefix-match containment. */
    public record PrefixSiblingFinding(ToolArgument argument, String probedPath,
                                       HttpRequestResponse response) {}

    public record ClassifiedFinding(PathTraversalTier tier, String differentialKey,
                                    ToolArgument argument, List<TraversalHit> evidence) {}

    /** Per-argument run outcome the classifier needs: the signature hits, and — per
     *  differentialKey — whether the literal {@code ../} was delivered to the handler and rejected
     *  there (vs a method-not-found / routing miss). Keys are namespaced by tool::argument so two
     *  arguments sharing a target do not cross-contaminate the differential. */
    record ProbeOutcomes(List<TraversalHit> hits, Set<String> plainDeliveredAndRejectedKeys) {}

    private final Http http;

    public ToolsCallTraversalProbeRunner(Http http) {
        this.http = http;
    }

    public List<DiscoveredTool> discoverTools(HttpRequest baseline) {
        return ToolsListDiscovery.discoverTools(http, baseline);
    }

    public List<ToolArgument> findPathArguments(List<DiscoveredTool> tools) {
        return ToolArgumentFinder.findArguments(tools, PathArgumentHeuristic::isPathLike);
    }

    public List<ClassifiedFinding> probeAndClassify(HttpRequest baseline,
                                                    List<ToolArgument> arguments,
                                                    List<ToolArgPayload> payloads) {
        List<ClassifiedFinding> findings = new ArrayList<>();
        for (ToolArgument argument : arguments) {
            findings.addAll(classify(argument, runArgument(baseline, argument, payloads)));
        }
        return findings;
    }

    ProbeOutcomes runArgument(HttpRequest baseline, ToolArgument argument, List<ToolArgPayload> payloads) {
        List<TraversalHit> hits = new ArrayList<>();
        Set<String> plainDeliveredAndRejected = new HashSet<>();
        for (ToolArgPayload payload : payloads) {
            HttpRequestResponse response = sendToolCall(baseline, argument, payload.value());
            if (responseMatchesSignature(response, payload.expectedSignatures())) {
                hits.add(new TraversalHit(argument, payload, response));
            } else if (payload.tier() == PathTraversalTier.TRAVERSAL
                    && literalPathDeliveredToHandler(response)) {
                plainDeliveredAndRejected.add(payload.differentialKey());
            }
        }
        return new ProbeOutcomes(hits, plainDeliveredAndRejected);
    }

    static List<ClassifiedFinding> classify(ToolArgument argument, ProbeOutcomes outcomes) {
        Map<String, List<TraversalHit>> hitsByKey = new LinkedHashMap<>();
        for (TraversalHit hit : outcomes.hits()) {
            hitsByKey.computeIfAbsent(hit.payload().differentialKey(), ignored -> new ArrayList<>())
                    .add(hit);
        }
        List<ClassifiedFinding> findings = new ArrayList<>();
        for (Map.Entry<String, List<TraversalHit>> entry : hitsByKey.entrySet()) {
            PathTraversalTier tier = TraversalTierClassifier.resolve(
                    entry.getValue().stream().map(hit -> hit.payload().tier()).toList(),
                    outcomes.plainDeliveredAndRejectedKeys().contains(entry.getKey()));
            findings.add(new ClassifiedFinding(tier, entry.getKey(), argument, entry.getValue()));
        }
        return findings;
    }

    // -------- CVE-2025-53110 prefix-sibling error-differential oracle --------

    /**
     * Probes each path argument for a naive-prefix-match root boundary (CVE-2025-53110) WITHOUT
     * reading any out-of-root secret. Derives the allowed root at runtime (a
     * {@code list_allowed_directories}-style tool, else a root leaked in a rejection error), sends a
     * DENY-CONTROL (a clearly out-of-root, non-prefix-sharing path) ONCE per derived root to confirm
     * THIS argument emits a distinguishable access-denied, then sends a NON-EXISTENT sibling that
     * shares the root's string prefix ({@code <root>_mcpscan_<marker>/<random>}). A prefix-match
     * server passes containment then fails to open the file → not-found, while the control was
     * denied → finding. A correctly-bounded server denies the sibling too → no finding. A server
     * that masks every rejection as not-found fails the control (not denied) → the oracle is blind
     * and skips, so it cannot be falsely reported.
     */
    public List<PrefixSiblingFinding> probePrefixSibling(HttpRequest baseline,
                                                         List<DiscoveredTool> discoveredTools,
                                                         List<ToolArgument> arguments) {
        List<String> discoveryToolNames = discoveredTools.stream().map(DiscoveredTool::name).toList();
        List<PrefixSiblingFinding> findings = new ArrayList<>();
        for (ToolArgument argument : arguments) {
            String root = AllowedRootDeriver.derive(
                    discoveryToolNames,
                    toolName -> sendNoArgToolCall(baseline, toolName),
                    probeValue -> sendToolCall(baseline, argument, probeValue));
            if (root == null) {
                continue;
            }
            String siblingPath = AllowedRootDeriver.prefixSiblingPath(root);
            if (siblingPath == null) {
                continue;
            }
            // One deny-control per derived root (not per payload) to limit traffic.
            HttpRequestResponse denyControl =
                    sendToolCall(baseline, argument, AllowedRootDeriver.DENY_CONTROL_PATH);
            HttpRequestResponse sibling = sendToolCall(baseline, argument, siblingPath);
            if (FilesystemErrorOracle.prefixSiblingConfirmed(denyControl, sibling)) {
                findings.add(new PrefixSiblingFinding(argument, siblingPath, sibling));
            }
        }
        return findings;
    }

    HttpRequestResponse sendToolCall(HttpRequest baseline, ToolArgument argument, String value) {
        return http.sendRequest(
                baseline.withBody(ToolsCallBodyBuilder.buildToolsCallBody(argument, value)));
    }

    private HttpRequestResponse sendNoArgToolCall(HttpRequest baseline, String toolName) {
        return http.sendRequest(baseline.withBody(ToolsCallBodyBuilder.buildNoArgToolsCallBody(toolName)));
    }

    private static boolean literalPathDeliveredToHandler(HttpRequestResponse response) {
        // For a tool argument the literal ../ is a plain JSON string that always reaches the
        // handler, so any response that is NOT a method-not-found / unknown-tool routing miss means
        // the handler ran and rejected the input (a tool-error envelope or a non-(-32601) error) —
        // the sanitizer-present signal the decode-after-check differential needs.
        if (response.response() == null || response.response().statusCode() != 200) {
            return false;
        }
        if (!McpRequestDetector.isMethodRecognised(response)) {
            return false;
        }
        return !McpRequestDetector.isToolCallSuccess(response);
    }

    private static boolean responseMatchesSignature(HttpRequestResponse response,
                                                    Set<FileSignature> expectedSignatures) {
        if (!McpRequestDetector.isToolCallSuccess(response)) {
            return false;
        }
        String body = McpRequestDetector.jsonRpcBody(response.response());
        if (body == null || body.isEmpty()) {
            return false;
        }
        for (String text : ToolCallTextExtractor.contentText(body)) {
            for (FileSignature signature : expectedSignatures) {
                if (signature.matches(text)) {
                    return true;
                }
            }
        }
        return false;
    }
}
