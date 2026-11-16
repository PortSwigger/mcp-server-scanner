package com.mcpscanner.automation;

import burp.api.montoya.scanner.audit.issues.AuditIssue;

import java.util.List;
import java.util.function.Function;

public record ReportedIssue(String name, String severity, String confidence, String baseUrl, String detail,
                            boolean extensionGenerated, List<String> checks) {

    static final int EXTENSION_GENERATED_TYPE_INDEX = 0x08000000;

    public ReportedIssue {
        checks = checks == null ? List.of() : List.copyOf(checks);
    }

    static ReportedIssue of(AuditIssue issue, Function<String, List<String>> checksReporting) {
        boolean extensionGenerated = issue.definition().typeIndex() == EXTENSION_GENERATED_TYPE_INDEX;
        return of(issue, extensionGenerated, extensionGenerated ? checksReporting.apply(issue.name()) : List.of());
    }

    static ReportedIssue filedByTheExtension(AuditIssue issue) {
        return of(issue, true, List.of());
    }

    private static ReportedIssue of(AuditIssue issue, boolean extensionGenerated, List<String> checks) {
        return new ReportedIssue(issue.name(), issue.severity().name(), issue.confidence().name(), issue.baseUrl(),
                issue.detail(), extensionGenerated, checks);
    }

    public ReportedIssue unattributed() {
        return new ReportedIssue(name, severity, confidence, baseUrl, detail, extensionGenerated, List.of());
    }
}
