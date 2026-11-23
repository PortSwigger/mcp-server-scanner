package com.mcpscanner.access;

import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.scanner.audit.issues.AuditIssue;

import java.util.List;
import java.util.concurrent.Executor;

public interface AccessComparisonRun extends AutoCloseable {

    default List<AuditIssue> compare(HttpRequestResponse ownerExchange) {
        return compare(ownerExchange, Runnable::run);
    }

    List<AuditIssue> compare(HttpRequestResponse ownerExchange, Executor identities);

    @Override
    void close();
}
