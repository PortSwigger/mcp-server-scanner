package com.mcpscanner.checks.registry;

import burp.api.montoya.scanner.audit.issues.AuditIssueSeverity;
import burp.api.montoya.scanner.scancheck.ScanCheckType;
import com.mcpscanner.checks.issue.Cwe;

import java.util.List;
import java.util.Objects;
import java.util.Optional;

public record CheckDescriptor(
        String id,
        String displayName,
        String description,
        AuditIssueSeverity headlineSeverity,
        ScanCheckType scope,
        boolean defaultEnabled,
        List<String> references,
        Optional<String> burpIssueName,
        String issueBackground,
        List<Cwe> cwes
) {
    public CheckDescriptor {
        if (id == null || id.isBlank()) {
            throw new IllegalArgumentException("id must not be null or blank");
        }
        if (displayName == null || displayName.isBlank()) {
            throw new IllegalArgumentException("displayName must not be null or blank");
        }
        Objects.requireNonNull(description, "description must not be null");
        Objects.requireNonNull(headlineSeverity, "headlineSeverity must not be null");
        Objects.requireNonNull(scope, "scope must not be null");
        Objects.requireNonNull(references, "references must not be null");
        Objects.requireNonNull(burpIssueName, "burpIssueName must not be null");
        Objects.requireNonNull(issueBackground, "issueBackground must not be null");
        Objects.requireNonNull(cwes, "cwes must not be null");
        for (String reference : references) {
            if (reference == null || reference.isBlank()) {
                throw new IllegalArgumentException(
                        "references must not contain null or blank entries: " + reference);
            }
        }
        burpIssueName.ifPresent(name -> {
            if (name.isBlank()) {
                throw new IllegalArgumentException("burpIssueName must not be blank when present");
            }
        });
        references = List.copyOf(references);
        cwes = List.copyOf(cwes);
    }

    public CheckDescriptor(
            String id,
            String displayName,
            String description,
            AuditIssueSeverity headlineSeverity,
            ScanCheckType scope,
            boolean defaultEnabled,
            List<String> references) {
        this(id, displayName, description, headlineSeverity, scope, defaultEnabled, references,
                Optional.empty(), "", List.of());
    }

    public CheckDescriptor(
            String id,
            String displayName,
            String description,
            AuditIssueSeverity headlineSeverity,
            ScanCheckType scope,
            boolean defaultEnabled,
            List<String> references,
            String issueBackground,
            List<Cwe> cwes) {
        this(id, displayName, description, headlineSeverity, scope, defaultEnabled, references,
                Optional.empty(), issueBackground, cwes);
    }

    public CheckDescriptor(
            String id,
            String displayName,
            String description,
            AuditIssueSeverity headlineSeverity,
            ScanCheckType scope,
            boolean defaultEnabled,
            List<String> references,
            Optional<String> burpIssueName) {
        this(id, displayName, description, headlineSeverity, scope, defaultEnabled, references,
                burpIssueName, "", List.of());
    }
}
