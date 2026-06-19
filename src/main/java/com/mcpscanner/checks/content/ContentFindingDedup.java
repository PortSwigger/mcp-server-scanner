package com.mcpscanner.checks.content;

import burp.api.montoya.http.HttpService;
import com.mcpscanner.mcp.McpRequestDetector;

import java.util.ArrayList;
import java.util.List;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Cross-surface dedup for content findings, shared by the connect-time
 * {@link DiscoveryContentScanner} (which emits via {@code siteMap().add(...)}) and the
 * passive {@code JsonRpcDiscoveryResponseScanner} (fed the same discovery responses at
 * connect time). Both run the same content rules over the same discovery metadata, so
 * without a shared claim set the same secret would be reported twice — once per surface —
 * a boundary Burp's own issue consolidation cannot bridge.
 *
 * <p>The claim is keyed on {@code (ruleId, matchedValue, host)} and is atomic:
 * {@link #tryClaim} returns {@code true} iff this call inserted the key. Whichever scanner
 * fires first for a given key wins; the other skips the duplicate. A finding only one
 * surface sees (e.g. a structured resource-template field the passive path never receives)
 * has an unclaimed key and still emits.
 *
 * <p>{@link #clear()} resets the set on disconnect so a reconnect re-reports.
 */
public final class ContentFindingDedup {

    private final Set<String> claimedFindings = ConcurrentHashMap.newKeySet();

    public boolean tryClaim(String ruleId, String matchedValue, String host) {
        return claimedFindings.add(key(ruleId, matchedValue, host));
    }

    /**
     * @return the subset of {@code findings} this call is the first to claim. A finding is
     * dropped when its {@code (ruleId, matchedValue, host)} key was already claimed — by the
     * other scanner sharing this instance, or by an earlier finding in the same surface
     * (collapsing a secret repeated across fields to a single issue).
     */
    public List<ContentFinding> claimUnseen(List<ContentFinding> findings, HttpService host) {
        String hostKey = McpRequestDetector.baseUrl(host);
        List<ContentFinding> unseen = new ArrayList<>(findings.size());
        for (ContentFinding finding : findings) {
            if (tryClaim(finding.rule().id(), finding.matchedText(), hostKey)) {
                unseen.add(finding);
            }
        }
        return unseen;
    }

    public void clear() {
        claimedFindings.clear();
    }

    private static String key(String ruleId, String matchedValue, String host) {
        return ruleId + "|" + matchedValue + "|" + host;
    }
}
