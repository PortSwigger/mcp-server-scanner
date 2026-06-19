package com.mcpscanner.ui.connect;

import com.mcpscanner.ui.state.ConnectPhase;

/**
 * Swing-free sink for connect-phase progress. The {@link ConnectCoordinator} reports each phase as
 * it advances; the SwingWorker shell adapts these into reducer {@code ConnectProgress} actions.
 */
@FunctionalInterface
public interface ProgressReporter {

    void report(ConnectPhase phase, String message);
}
