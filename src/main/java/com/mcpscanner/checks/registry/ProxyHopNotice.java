package com.mcpscanner.checks.registry;

import burp.api.montoya.scanner.audit.issues.AuditIssue;
import com.mcpscanner.checks.api.CheckLog;
import com.mcpscanner.mcp.ScannerSentinels;

import java.util.List;

final class ProxyHopNotice {

    private ProxyHopNotice() {
    }

    static void noteStillProxied(List<AuditIssue> issues, CheckLog log) {
        long stillProxied = issues.stream().flatMap(issue -> issue.requestResponses().stream())
                .filter(item -> item != null && item.response() != null)
                .filter(item -> item.response().hasHeader(ScannerSentinels.EXCHANGE_HEADER)).count();
        if (stillProxied > 0) {
            log.warn("issue evidence still shows the proxy hop for " + stillProxied
                    + " exchange(s): the upstream exchange was no longer stored, so the sentinel was stripped as a backstop");
        }
    }
}
