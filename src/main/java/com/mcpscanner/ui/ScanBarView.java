package com.mcpscanner.ui;

interface ScanBarView {

    ScanBarView NONE = new ScanBarView() {
    };

    default void forgetPlannedCounts() {
    }

    default boolean refreshUnlessStarting() {
        return true;
    }

    default void refreshScanHint() {
    }

    default void refreshChecksSummary() {
    }

    default void refreshActivity() {
    }

    default void showConnected(boolean connected) {
    }

    default void showStarting() {
    }
}
