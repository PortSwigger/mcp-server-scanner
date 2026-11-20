package com.mcpscanner.access.listing;

import burp.api.montoya.scanner.audit.issues.AuditIssueConfidence;
import burp.api.montoya.scanner.audit.issues.AuditIssueSeverity;
import com.mcpscanner.access.SyntheticCall;

import java.util.Collections;
import java.util.List;
import java.util.Set;
import java.util.TreeSet;

record ListingFinding(ListingIssueKind kind, ToolList synthetic, List<ToolList> exceeded, Set<String> extraTools,
                      List<SyntheticCall> confirmations) {

    ListingFinding {
        exceeded = List.copyOf(exceeded);
        extraTools = Collections.unmodifiableSortedSet(new TreeSet<>(extraTools));
        confirmations = List.copyOf(confirmations);
    }

    boolean confirmed() {
        return !confirmations.isEmpty();
    }

    AuditIssueSeverity severity() {
        return kind.severity(confirmed());
    }

    AuditIssueConfidence confidence() {
        return kind.confidence(confirmed());
    }
}
