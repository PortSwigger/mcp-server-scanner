package com.mcpscanner.automation;

import burp.api.montoya.core.Registration;
import burp.api.montoya.http.Http;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.scanner.AuditConfiguration;
import burp.api.montoya.scanner.BuiltInAuditConfiguration;
import burp.api.montoya.scanner.Scanner;
import burp.api.montoya.scanner.audit.Audit;
import burp.api.montoya.scanner.audit.issues.AuditIssue;
import burp.api.montoya.scanner.audit.issues.AuditIssueConfidence;
import burp.api.montoya.scanner.audit.issues.AuditIssueSeverity;
import burp.api.montoya.scanner.scancheck.ActiveScanCheck;
import burp.api.montoya.scanner.scancheck.ScanCheckType;
import com.mcpscanner.checks.api.CheckDescriptor;
import com.mcpscanner.checks.api.CheckKind;
import com.mcpscanner.checks.api.RequestCheck;
import com.mcpscanner.http.BareRequests;
import com.mcpscanner.http.EmptyResponse;

import java.time.Duration;
import java.util.List;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.function.Function;

public final class AuditPathCanary {

    static final Duration AUDIT_BUDGET = Duration.ofMinutes(10);
    private static final Duration EXTENSION_SEND_INTERVAL = Duration.ofMillis(500);
    private static final int EXTENSION_SENDS = 6;

    private static final CheckDescriptor DESCRIPTOR = new CheckDescriptor("automation-audit-path-canary",
            "Audit path canary", "Sends a write through the scanner's Http after extension traffic (harness only).",
            CheckKind.REQUEST, AuditIssueSeverity.INFORMATION, AuditIssueConfidence.TENTATIVE, true, List.of());

    private final Scanner scanner;
    private final Http extensionHttp;
    private final Function<RequestCheck, ActiveScanCheck> asProductionScanCheck;

    public AuditPathCanary(Scanner scanner, Http extensionHttp,
                           Function<RequestCheck, ActiveScanCheck> asProductionScanCheck) {
        this.scanner = scanner;
        this.extensionHttp = extensionHttp;
        this.asProductionScanCheck = asProductionScanCheck;
    }

    public AuditPathCanaryReport run(AuditPathCanaryCommand command) {
        WriteAfterExtensionTraffic check = new WriteAfterExtensionTraffic(command.url());
        Registration registration = scanner.registerActiveScanCheck(asProductionScanCheck.apply(check),
                ScanCheckType.PER_REQUEST);
        Audit audit = scanner.startAudit(AuditConfiguration.auditConfiguration(
                BuiltInAuditConfiguration.LEGACY_ACTIVE_AUDIT_CHECKS));
        try {
            audit.addRequest(BareRequests.fromUrl(command.url()));
            return check.report.get(AUDIT_BUDGET.toMillis(), TimeUnit.MILLISECONDS);
        } catch (InterruptedException interrupted) {
            Thread.currentThread().interrupt();
            throw new IllegalStateException("interrupted while waiting for the audit path canary", interrupted);
        } catch (ExecutionException | TimeoutException failed) {
            throw new IllegalStateException("the audit path canary did not run", failed);
        } finally {
            registration.deregister();
            audit.delete();
        }
    }

    private final class WriteAfterExtensionTraffic implements RequestCheck {

        private final String url;
        private final AtomicBoolean claimed = new AtomicBoolean();
        private final CompletableFuture<AuditPathCanaryReport> report = new CompletableFuture<>();

        private WriteAfterExtensionTraffic(String url) {
            this.url = url;
        }

        @Override
        public CheckDescriptor descriptor() {
            return DESCRIPTOR;
        }

        @Override
        public List<AuditIssue> audit(HttpRequestResponse base, Http scan) {
            if (base.request().url().startsWith(url) && claimed.compareAndSet(false, true)) {
                try {
                    report.complete(writeAfterExtensionTraffic(scan));
                } catch (RuntimeException failed) {
                    report.completeExceptionally(failed);
                }
            }
            return List.of();
        }

        private AuditPathCanaryReport writeAfterExtensionTraffic(Http scan) {
            HttpRequest read = BareRequests.fromUrl(url);
            int unanswered = answered(extensionHttp.sendRequest(read)) ? 0 : 1;
            scan.sendRequest(read);
            for (int send = 0; send < EXTENSION_SENDS; send++) {
                pause(EXTENSION_SEND_INTERVAL);
                unanswered += answered(extensionHttp.sendRequest(read)) ? 0 : 1;
            }
            HttpRequest write = read.withMethod("POST").withBody("{\"canary\":\"write\"}");
            return new AuditPathCanaryReport(unanswered, answered(scan.sendRequest(write)));
        }
    }

    private static boolean answered(HttpRequestResponse exchange) {
        return exchange != null && exchange.response() != null && !EmptyResponse.is(exchange.response());
    }

    private static void pause(Duration interval) {
        try {
            Thread.sleep(interval.toMillis());
        } catch (InterruptedException interrupted) {
            Thread.currentThread().interrupt();
            throw new IllegalStateException("interrupted between extension sends", interrupted);
        }
    }
}
