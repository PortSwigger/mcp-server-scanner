package com.mcpscanner.automation;

import burp.api.montoya.scanner.audit.Audit;
import burp.api.montoya.sitemap.SiteMap;
import com.mcpscanner.scan.BurpAuditRun;
import com.mcpscanner.scan.RunningScan;

import java.util.Optional;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.BooleanSupplier;
import java.util.function.IntSupplier;
import java.util.function.Supplier;

public final class LaunchedAudit {

    static final String FINISHED = "finished";
    static final String AWAITING_COLLABORATOR = "awaiting Collaborator interactions";

    private final SiteMap siteMap;
    private final CheckTelemetry telemetry;
    private final IntSupplier builtInRequestsDiverted;
    private final BooleanSupplier collaboratorSettled;
    private final AtomicReference<Audit> current = new AtomicReference<>();

    public LaunchedAudit(SiteMap siteMap, CheckTelemetry telemetry, IntSupplier builtInRequestsDiverted) {
        this(siteMap, telemetry, builtInRequestsDiverted, () -> true);
    }

    public LaunchedAudit(SiteMap siteMap, CheckTelemetry telemetry, IntSupplier builtInRequestsDiverted,
                         BooleanSupplier collaboratorSettled) {
        this.siteMap = siteMap;
        this.telemetry = telemetry;
        this.builtInRequestsDiverted = builtInRequestsDiverted;
        this.collaboratorSettled = collaboratorSettled;
    }

    void start(Supplier<RunningScan> launch) {
        telemetry.reset();
        current.set(auditOf(launch.get()));
    }

    public Optional<AuditSnapshot> snapshot() {
        return Optional.ofNullable(current.get()).map(this::snapshotOf);
    }

    private static Audit auditOf(RunningScan scan) {
        if (scan instanceof BurpAuditRun burpAudit) {
            return burpAudit.audit();
        }
        throw new IllegalStateException("Headless scans report on a Burp audit, not " + scan);
    }

    private String status(Audit audit) {
        String status = audit.statusMessage();
        return FINISHED.equalsIgnoreCase(status) && !collaboratorSettled.getAsBoolean() ? AWAITING_COLLABORATOR : status;
    }

    private AuditSnapshot snapshotOf(Audit audit) {
        return new AuditSnapshot(status(audit), audit.requestCount(), audit.errorCount(),
                audit.insertionPointCount(), telemetry.sent(), telemetry.reached(),
                siteMap.issues().stream().map(issue -> ReportedIssue.of(issue, telemetry::checksReporting)).toList(),
                builtInRequestsDiverted.getAsInt(), telemetry.probesByCheck());
    }
}
