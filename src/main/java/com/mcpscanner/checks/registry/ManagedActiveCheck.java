package com.mcpscanner.checks.registry;

import burp.api.montoya.http.Http;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.scanner.AuditResult;
import burp.api.montoya.scanner.ConsolidationAction;
import burp.api.montoya.scanner.Scanner;
import burp.api.montoya.scanner.audit.insertionpoint.AuditInsertionPoint;
import burp.api.montoya.scanner.audit.issues.AuditIssue;
import burp.api.montoya.scanner.scancheck.ActiveScanCheck;
import com.mcpscanner.logging.McpEventLog;

import java.util.List;
import java.util.Objects;

public abstract class ManagedActiveCheck implements ActiveScanCheck, ManagedCheck {

    private final ScanCheckSettings settings;
    private final McpEventLog eventLog;

    protected ManagedActiveCheck(ScanCheckSettings settings) {
        this(settings, null);
    }

    protected ManagedActiveCheck(ScanCheckSettings settings, McpEventLog eventLog) {
        this.settings = Objects.requireNonNull(settings, "settings must not be null");
        this.eventLog = eventLog;
    }

    protected final McpEventLog eventLog() {
        return eventLog;
    }

    protected final boolean isEnabledByDescriptor() {
        CheckDescriptor descriptor = descriptor();
        return settings.isEnabled(descriptor.id(), descriptor.defaultEnabled());
    }

    @Override
    public abstract CheckDescriptor descriptor();

    protected abstract AuditResult runCheck(HttpRequestResponse baseRequestResponse,
                                            AuditInsertionPoint insertionPoint,
                                            Http http);

    @Override
    public final void registerWith(Scanner scanner) {
        scanner.registerActiveScanCheck(this, descriptor().scope());
    }

    @Override
    public final String checkName() {
        CheckDescriptor descriptor = descriptor();
        return descriptor.burpIssueName().orElse(descriptor.displayName());
    }

    @Override
    public final AuditResult doCheck(HttpRequestResponse baseRequestResponse,
                                     AuditInsertionPoint insertionPoint,
                                     Http http) {
        if (!isEnabledByDescriptor()) {
            return AuditResult.auditResult(List.of());
        }
        return ScanCheckLogging.runAndLog(eventLog, descriptor().id(),
                () -> runCheck(baseRequestResponse, insertionPoint, http));
    }

    protected final ConsolidationAction consolidateByName(String issueName,
                                                          AuditIssue existingIssue,
                                                          AuditIssue newIssue) {
        Objects.requireNonNull(issueName, "issueName must not be null");
        if (issueName.equals(existingIssue.name()) && issueName.equals(newIssue.name())) {
            return ConsolidationAction.KEEP_EXISTING;
        }
        return ConsolidationAction.KEEP_BOTH;
    }
}
