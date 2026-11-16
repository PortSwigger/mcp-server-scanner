package com.mcpscanner.scan;

public interface RunningScan {

    ScanActivity activity();

    boolean isFinished();

    boolean outlivesConnection();

    void cancel();

    default void failWith(String reason) {
        cancel();
    }

    default boolean pollEnded() {
        return isFinished();
    }

    void whenEnded(Runnable action);

    default void stopWatching() {
    }
}
