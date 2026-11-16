package com.mcpscanner.checks.registry;

import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.scanner.audit.insertionpoint.AuditInsertionPoint;

@FunctionalInterface
public interface ProbeCalls {

    ProbeCalls NONE = base -> false;

    boolean include(HttpRequestResponse base);

    default boolean fuzzesAddedLeaf(HttpRequestResponse base, AuditInsertionPoint insertionPoint) {
        return true;
    }
}
