package com.mcpscanner.ui;

import com.mcpscanner.scan.request.GeneratedScan;
import com.mcpscanner.scan.request.ScanMessage;

import java.util.List;

record PlannedRequests(List<String> subjects) {

    PlannedRequests {
        subjects = List.copyOf(subjects);
    }

    static PlannedRequests of(GeneratedScan scan) {
        return new PlannedRequests(scan.messages().stream().map(ScanMessage::subject).toList());
    }

    int count() {
        return subjects.size();
    }

    String listing() {
        return String.join(", ", subjects.stream().distinct().toList());
    }
}
