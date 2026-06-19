package com.mcpscanner.checks.registry;

/**
 * Implemented by checks that hold per-connection dedup state (claim sets keyed on the target
 * host) which must be dropped on disconnect, so a reconnect re-probes each host instead of
 * the set growing unbounded across a long-lived Burp project.
 */
public interface SessionScopedCheck {

    void clearSessionState();
}
