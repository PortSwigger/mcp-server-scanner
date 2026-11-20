package com.mcpscanner.cvetargets.burp;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.mcpscanner.automation.AuditPathCanaryCommand;
import com.mcpscanner.automation.AuditPathCanaryReport;
import com.mcpscanner.automation.AuditSnapshot;
import com.mcpscanner.automation.AuthProbeCommand;
import com.mcpscanner.automation.AuthProbeReport;
import com.mcpscanner.automation.AutomationServer;
import com.mcpscanner.automation.CheckAccessCommand;
import com.mcpscanner.automation.CheckAccessStatus;
import com.mcpscanner.automation.LaunchedScan;
import com.mcpscanner.automation.ScanAllCommand;
import com.mcpscanner.automation.SendCanaryCommand;
import com.mcpscanner.automation.SendCanaryReport;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.Optional;

final class HttpBurpAutomation implements BurpAutomation, SendLatencyCanary, AuthProbeCanary, AuditSendCanary {

    private static final ObjectMapper JSON = new ObjectMapper();
    private static final Duration SCAN_ALL_TIMEOUT = Duration.ofMinutes(5);
    private static final Duration SEND_CANARY_TIMEOUT = Duration.ofMinutes(5);
    private static final Duration AUTH_PROBE_TIMEOUT = Duration.ofMinutes(1);
    private static final Duration AUDIT_PATH_CANARY_TIMEOUT = Duration.ofMinutes(11);
    private static final Duration AUDIT_TIMEOUT = Duration.ofSeconds(30);
    private static final int NOT_FOUND = 404;

    private final HttpClient client = HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(5)).build();
    private final URI base;

    HttpBurpAutomation(int port) {
        this.base = URI.create("http://127.0.0.1:" + port);
    }

    boolean answers() {
        try {
            send(HttpRequest.newBuilder(base.resolve("/audit")).timeout(Duration.ofSeconds(2)).GET().build());
            return true;
        } catch (UncheckedIOException notListening) {
            return false;
        }
    }

    @Override
    public LaunchedScan scanAll(ScanAllCommand command) {
        return parsed(post("/scan-all", command, SCAN_ALL_TIMEOUT), LaunchedScan.class, "Scan all");
    }

    @Override
    public SendCanaryReport sendCanary(SendCanaryCommand command) {
        return parsed(post("/send-canary", command, SEND_CANARY_TIMEOUT), SendCanaryReport.class, "Send canary");
    }

    @Override
    public AuditPathCanaryReport auditPathCanary(AuditPathCanaryCommand command) {
        return parsed(post("/audit-path-canary", command, AUDIT_PATH_CANARY_TIMEOUT), AuditPathCanaryReport.class,
                "Audit path canary");
    }

    @Override
    public AuthProbeReport authProbe(AuthProbeCommand command) {
        return parsed(post("/auth-probe", command, AUTH_PROBE_TIMEOUT), AuthProbeReport.class, "Auth probe");
    }

    @Override
    public Optional<AuditSnapshot> audit() {
        return reported("/audit", AuditSnapshot.class, "Audit status");
    }

    @Override
    public CheckAccessStatus checkAccess(CheckAccessCommand command) {
        HttpResponse<String> response = send(HttpRequest.newBuilder(base.resolve(AutomationServer.CHECK_ACCESS_PATH))
                .timeout(SCAN_ALL_TIMEOUT)
                .header("Content-Type", "application/json")
                .POST(HttpRequest.BodyPublishers.ofString(json(command)))
                .build());
        return parsed(response, CheckAccessStatus.class, "Check access");
    }

    @Override
    public Optional<CheckAccessStatus> checkAccessStatus() {
        return reported(AutomationServer.CHECK_ACCESS_PATH, CheckAccessStatus.class, "Check access status");
    }

    private <T> Optional<T> reported(String path, Class<T> type, String operation) {
        HttpResponse<String> response = send(HttpRequest.newBuilder(base.resolve(path)).timeout(AUDIT_TIMEOUT)
                .GET().build());
        return response.statusCode() == NOT_FOUND
                ? Optional.empty()
                : Optional.of(parsed(response, type, operation));
    }

    private HttpResponse<String> post(String path, Object command, Duration timeout) {
        return send(HttpRequest.newBuilder(base.resolve(path))
                .timeout(timeout)
                .header("Content-Type", "application/json")
                .POST(HttpRequest.BodyPublishers.ofString(json(command)))
                .build());
    }

    private HttpResponse<String> send(HttpRequest request) {
        try {
            return client.send(request, HttpResponse.BodyHandlers.ofString());
        } catch (IOException failure) {
            throw new UncheckedIOException(failure);
        } catch (InterruptedException interrupted) {
            Thread.currentThread().interrupt();
            throw new IllegalStateException("interrupted while talking to Burp", interrupted);
        }
    }

    private static <T> T parsed(HttpResponse<String> response, Class<T> type, String operation) {
        if (response.statusCode() != 200) {
            throw new IllegalStateException(operation + " in Burp failed (" + response.statusCode() + "): "
                    + response.body());
        }
        try {
            return JSON.readValue(response.body(), type);
        } catch (IOException unreadable) {
            throw new UncheckedIOException(unreadable);
        }
    }

    private static String json(Object value) {
        try {
            return JSON.writeValueAsString(value);
        } catch (IOException unwritable) {
            throw new UncheckedIOException(unwritable);
        }
    }
}
