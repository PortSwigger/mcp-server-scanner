package com.mcpscanner.automation;

import java.util.List;

public record SendCanaryReport(List<Long> latenciesMicros, long wallMicros, int unanswered) {

    public SendCanaryReport {
        latenciesMicros = List.copyOf(latenciesMicros);
    }
}
