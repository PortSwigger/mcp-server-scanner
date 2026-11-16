package com.mcpscanner.checks.registry;

import burp.api.montoya.scanner.scancheck.ActiveScanCheck;
import com.mcpscanner.checks.api.CheckCatalog;
import com.mcpscanner.checks.api.McpCheck;
import com.mcpscanner.checks.api.SkipReason;
import com.mcpscanner.checks.shared.scancontext.ScanNotices;
import com.mcpscanner.http.ConnectionReuse;
import com.mcpscanner.http.UpstreamExchanges;
import com.mcpscanner.logging.McpEventLog;

import java.util.List;
import java.util.Objects;
import java.util.Optional;

public final class ScanCheckRegistry {

    private final List<McpCheckAdapter<?>> checks;
    private final ScanCheckSettings settings;
    private final ScanNotices auditNotices = new ScanNotices();

    public ScanCheckRegistry(CheckCatalog catalog, ScanCheckSettings settings, McpEventLog eventLog) {
        this(catalog, settings, eventLog, CheckInstrumentation.NONE);
    }

    public ScanCheckRegistry(CheckCatalog catalog, ScanCheckSettings settings, McpEventLog eventLog,
                             CheckInstrumentation instrumentation) {
        this(catalog, settings, eventLog, instrumentation, UpstreamExchanges.NONE);
    }

    public ScanCheckRegistry(CheckCatalog catalog, ScanCheckSettings settings, McpEventLog eventLog,
                             CheckInstrumentation instrumentation, UpstreamExchanges upstreamExchanges) {
        this(catalog, settings, eventLog, instrumentation, upstreamExchanges, ConnectionReuse.withoutLocalAnswers());
    }

    public ScanCheckRegistry(CheckCatalog catalog, ScanCheckSettings settings, McpEventLog eventLog,
                             CheckInstrumentation instrumentation, UpstreamExchanges upstreamExchanges,
                             ConnectionReuse connectionReuse) {
        this(catalog, settings, eventLog, instrumentation, upstreamExchanges, connectionReuse, IssueDestination.NONE);
    }

    public ScanCheckRegistry(CheckCatalog catalog, ScanCheckSettings settings, McpEventLog eventLog,
                             CheckInstrumentation instrumentation, UpstreamExchanges upstreamExchanges,
                             ConnectionReuse connectionReuse, IssueDestination issuesBurpWouldDrop) {
        this(catalog, settings, eventLog, instrumentation, upstreamExchanges, connectionReuse, issuesBurpWouldDrop,
                ProbeCalls.NONE);
    }

    public ScanCheckRegistry(CheckCatalog catalog, ScanCheckSettings settings, McpEventLog eventLog,
                             CheckInstrumentation instrumentation, UpstreamExchanges upstreamExchanges,
                             ConnectionReuse connectionReuse, IssueDestination issuesBurpWouldDrop,
                             ProbeCalls probeCalls) {
        Objects.requireNonNull(catalog, "catalog must not be null");
        this.settings = Objects.requireNonNull(settings, "settings must not be null");
        McpCheckAdapters adapters = new McpCheckAdapters(settings, eventLog, instrumentation, upstreamExchanges,
                connectionReuse, issuesBurpWouldDrop, auditNotices, probeCalls);
        this.checks = catalog.all().stream().<McpCheckAdapter<?>>map(adapters::adapt).toList();
    }

    public List<ManagedCheck> all() {
        return List.copyOf(checks);
    }

    public long enabledActiveCheckCount() {
        return checks.stream()
                .map(ManagedCheck::descriptor)
                .filter(descriptor -> settings.isEnabled(descriptor.id(), descriptor.defaultEnabled()))
                .count();
    }

    public void registerWith(ActiveCheckRegistrar registrar) {
        checks.forEach(check -> check.registerWith(registrar));
    }

    Optional<McpCheckAdapter<?>> adapterRunning(McpCheck check) {
        return checks.stream().filter(adapter -> adapter.runs(check)).findFirst();
    }

    public void invocationsSkipped(ActiveScanCheck check, int invocations, SkipReason reason) {
        checks.stream().filter(adapter -> adapter == check)
                .forEach(adapter -> adapter.invocationsSkipped(invocations, reason));
    }

    public void auditStarting() {
        auditNotices.forget();
    }

    public void clearConnectionState() {
        checks.forEach(McpCheckAdapter::clearConnectionState);
    }
}
