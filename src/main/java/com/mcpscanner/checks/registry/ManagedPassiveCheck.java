package com.mcpscanner.checks.registry;

import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.scanner.AuditResult;
import burp.api.montoya.scanner.Scanner;
import burp.api.montoya.scanner.scancheck.PassiveScanCheck;
import com.mcpscanner.logging.McpEventLog;

import java.util.List;
import java.util.Objects;

public abstract class ManagedPassiveCheck implements PassiveScanCheck, ManagedCheck {

    private final ScanCheckSettings settings;
    private final McpEventLog eventLog;

    protected ManagedPassiveCheck(ScanCheckSettings settings) {
        this(settings, null);
    }

    protected ManagedPassiveCheck(ScanCheckSettings settings, McpEventLog eventLog) {
        this.settings = Objects.requireNonNull(settings, "settings must not be null");
        this.eventLog = eventLog;
    }

    @Override
    public abstract CheckDescriptor descriptor();

    protected abstract AuditResult runCheck(HttpRequestResponse baseRequestResponse);

    @Override
    public final void registerWith(Scanner scanner) {
        scanner.registerPassiveScanCheck(this, descriptor().scope());
    }

    @Override
    public final String checkName() {
        CheckDescriptor descriptor = descriptor();
        return descriptor.burpIssueName().orElse(descriptor.displayName());
    }

    @Override
    public final AuditResult doCheck(HttpRequestResponse baseRequestResponse) {
        CheckDescriptor descriptor = descriptor();
        if (!settings.isEnabled(descriptor.id(), descriptor.defaultEnabled())) {
            return AuditResult.auditResult(List.of());
        }
        return ScanCheckLogging.runAndLog(eventLog, descriptor.id(),
                () -> runCheck(baseRequestResponse));
    }
}
