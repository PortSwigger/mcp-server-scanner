package com.mcpscanner.scan;

import burp.api.montoya.http.Http;
import burp.api.montoya.scanner.audit.issues.AuditIssue;

import java.util.List;

/**
 * A check that runs once per scan, driven from {@link McpScanLauncher} using the
 * live {@link ScanStartContext} (endpoint + connect-time headers) rather than a
 * Burp-supplied baseline request.
 *
 * <p>Some preconditions can only be satisfied by the connect-time session:
 * the OAuth token validator needs the live bearer (Burp's baseline carries no
 * auth on no-auth-required servers), and the DCR probe needs the AS metadata
 * that connect-time discovery already discovered. Implementations are expected
 * to dedup internally against the launcher path AND the regular Burp scan-check
 * path so the same finding doesn't surface twice in the issues panel.
 */
public interface ScanStartCheck {

    /**
     * @return audit issues emitted by this check at scan-start, or an empty list
     * if the precondition is not met. Implementations MUST NOT throw — log and
     * return empty instead.
     */
    List<AuditIssue> runOnceForSession(ScanStartContext context, Http http);
}
