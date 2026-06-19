package com.mcpscanner.ui.connect;

import com.mcpscanner.auth.OAuthAuthCodeStrategy;
import com.mcpscanner.client.ConnectResult;

/**
 * Outcome of a {@link ConnectCoordinator#connect} run. Carries the upstream connect result plus the
 * OAuth strategy captured during the dance (null for non-OAuth attempts). The connected status is
 * deliberately NOT built here — the SwingWorker shell builds it in {@code done()} so the EDT-bound
 * status construction keeps its original timing.
 */
public record ConnectionAttemptResult(ConnectResult result, OAuthAuthCodeStrategy oauthStrategy) {
}
