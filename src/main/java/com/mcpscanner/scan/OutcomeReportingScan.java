package com.mcpscanner.scan;

import java.util.function.Consumer;

public interface OutcomeReportingScan extends RunningScan {

    void whenCompleted(Consumer<ScanOutcome> listener);
}
