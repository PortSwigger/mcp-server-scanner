package com.mcpscanner.checks.registry;

import burp.api.montoya.http.Http;
import burp.api.montoya.scanner.Scanner;
import burp.api.montoya.scanner.audit.issues.AuditIssue;
import com.mcpscanner.logging.McpEventLog;
import com.mcpscanner.scan.ScanStartCheck;
import com.mcpscanner.scan.ScanStartContext;

import java.util.List;
import java.util.Objects;

/**
 * Base class for checks that run once per scan-start (driven by the launcher from the live
 * session) rather than on every Burp-supplied per-request baseline.
 *
 * <p>Parallel to {@link ManagedActiveCheck}/{@link ManagedPassiveCheck}: it owns the toggle
 * gate and lifecycle logging so subclasses only supply a {@link CheckDescriptor} and a
 * {@link #probe} body. Unlike the active/passive bases it is NOT a Burp per-request scan check,
 * so {@link #registerWith(Scanner)} is a no-op — these checks self-discover everything they need
 * from the {@link ScanStartContext} and would only double-report if also registered per-request.
 */
public abstract class ManagedScanStartCheck implements ManagedCheck, ScanStartCheck {

    private final ScanCheckSettings settings;
    private final McpEventLog eventLog;

    protected ManagedScanStartCheck(ScanCheckSettings settings) {
        this(settings, null);
    }

    protected ManagedScanStartCheck(ScanCheckSettings settings, McpEventLog eventLog) {
        this.settings = Objects.requireNonNull(settings, "settings must not be null");
        this.eventLog = eventLog;
    }

    protected final McpEventLog eventLog() {
        return eventLog;
    }

    @Override
    public abstract CheckDescriptor descriptor();

    protected abstract List<AuditIssue> probe(ScanStartContext context, Http http);

    @Override
    public final void registerWith(Scanner scanner) {
        // No-op: scan-start checks are not Burp per-request scan checks.
    }

    public final String checkName() {
        CheckDescriptor descriptor = descriptor();
        return descriptor.burpIssueName().orElse(descriptor.displayName());
    }

    @Override
    public final List<AuditIssue> runOnceForSession(ScanStartContext context, Http http) {
        CheckDescriptor descriptor = descriptor();
        if (!settings.isEnabled(descriptor.id(), descriptor.defaultEnabled())) {
            return List.of();
        }
        return ScanCheckLogging.runIssuesAndLog(eventLog, descriptor.id(), () -> probe(context, http));
    }
}
