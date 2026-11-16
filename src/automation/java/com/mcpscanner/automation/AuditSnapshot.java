package com.mcpscanner.automation;

import java.util.List;
import java.util.Map;

public record AuditSnapshot(String status, int requestCount, int errorCount, int insertionPointCount,
                            int extensionRequestsSent, int extensionRequestsReached, List<ReportedIssue> issues,
                            int builtInRequestsDiverted, Map<String, CheckProbes> probesByCheck) {

    public AuditSnapshot {
        issues = List.copyOf(issues);
        probesByCheck = probesByCheck == null ? Map.of() : Map.copyOf(probesByCheck);
    }
}
