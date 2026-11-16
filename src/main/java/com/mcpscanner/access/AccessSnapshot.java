package com.mcpscanner.access;

import com.mcpscanner.checks.api.Principal;

import java.util.List;

public record AccessSnapshot(boolean connected, List<Principal> principals, List<AccessRow> rows) {

    public AccessSnapshot {
        principals = List.copyOf(principals);
        rows = List.copyOf(rows);
    }

    public List<AccessRow> rows(AccessFilter filter) {
        return rows.stream().filter(filter).toList();
    }

    public List<Principal> comparedIdentities() {
        return principals.stream().filter(principal -> !principal.id().equals(Principal.PRIMARY_ID)).toList();
    }

    public long anomalies() {
        return rows.stream().mapToLong(AccessRow::anomalies).sum();
    }

    public long issues() {
        return rows.stream().mapToLong(AccessRow::issues).sum();
    }

    public List<AccessRow> unconfirmedSameResults() {
        return rows.stream().filter(row -> row.unconfirmedSameResult(principals)).toList();
    }

    public boolean checked() {
        return rows.stream().anyMatch(AccessRow::checked);
    }
}
