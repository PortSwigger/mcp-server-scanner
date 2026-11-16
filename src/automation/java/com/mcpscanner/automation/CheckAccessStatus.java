package com.mcpscanner.automation;

import java.util.List;

public record CheckAccessStatus(CheckAccessPhase status, int checked, int total, int requestsSent,
                                int requestsReached, List<ReportedIssue> issues, String reason) {

    public CheckAccessStatus {
        issues = issues == null ? List.of() : List.copyOf(issues);
    }
}
