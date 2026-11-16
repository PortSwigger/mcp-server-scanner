package com.mcpscanner.proxy;

import com.mcpscanner.client.HttpAuthResponses;
import com.mcpscanner.client.McpScannerSession;
import com.mcpscanner.mcp.McpHeaders;
import com.mcpscanner.mcp.McpRequestDetector;
import com.mcpscanner.core.connection.ConnectionAuthException;
import com.mcpscanner.core.connection.OperationRecovery;
import com.mcpscanner.core.connection.RecoveryResult;
import com.mcpscanner.core.protocol.McpFlow;

import java.io.IOException;
import java.util.HashMap;
import java.util.Map;
import java.util.Objects;
import java.util.TreeMap;

final class SseForwarding implements ForwardingStrategy {

    private static final int MAX_RECOVERY_ATTEMPTS = 2;

    private record Operation(Map<String, String> headers, boolean explicitCredentials) {}

    private final McpScannerSession scannerSession;
    private final ProvenanceGuard guard;
    private final SseSessionPool sessions;

    SseForwarding(McpScannerSession scannerSession, ProvenanceGuard guard, SseSessionPool sessions) {
        this.scannerSession = scannerSession;
        this.guard = guard;
        this.sessions = sessions;
    }

    @Override
    public String label() {
        return "SSE proxy";
    }

    @Override
    public ProxyResponse forward(String body, Map<String, String> headers, AuditRequest audit)
            throws IOException, InterruptedException {
        if (SentinelHeaders.hasStripAuth(headers) && SentinelHeaders.hasKeepSession(headers)) {
            return forwardOnLiveStream(body, headers, audit);
        }
        if (SentinelHeaders.hasIdentity(headers) || SentinelHeaders.hasStripAuth(headers)) {
            return sessions.forwardIsolated(audit.connection(), SentinelHeaders.withoutSentinels(headers), body, headers);
        }
        if (audit.status() == AuditProvenance.Status.MANUAL) {
            return sessions.forwardIsolated(audit.connection(), headers, body, headers);
        }
        if (McpRequestDetector.isInitializeBody(body)) {
            return forwardOnAStreamOfItsOwn(body, headers, audit);
        }
        return forwardManaged(body, headers, audit);
    }

    private ProxyResponse forwardOnAStreamOfItsOwn(String body, Map<String, String> headers, AuditRequest audit)
            throws IOException, InterruptedException {
        Map<String, String> sessionHeaders = sessions.managed(audit.connection()).headers();
        return sessions.forwardIsolated(audit.connection(), sessionHeaders, body,
                operation(headers, sessionHeaders, audit.isManaged()).headers());
    }

    private ProxyResponse forwardOnLiveStream(String body, Map<String, String> headers, AuditRequest audit)
            throws IOException, InterruptedException {
        return sessions.managed(audit.connection()).session().forwardRequest(body, headers);
    }

    private ProxyResponse forwardManaged(String body, Map<String, String> headers, AuditRequest audit)
            throws IOException, InterruptedException {
        OperationRecovery recovery = guard.use(audit.connection(), scannerSession::beginAuthOperation);
        Operation operation = null;
        for (int attempt = 0; ; attempt++) {
            SseSessionPool.Lease lease = sessions.managed(audit.connection());
            if (operation == null) operation = operation(headers, lease.headers(), audit.isManaged());
            ProxyResponse response = lease.session().forwardRequest(body, operation.headers());
            if (!HttpAuthResponses.isAuthChallenge(response.statusCode())) return response;
            sessions.retire(lease.session());
            if (operation.explicitCredentials() || attempt == MAX_RECOVERY_ATTEMPTS) return response;
            if (!recovered(recovery, response, audit.connection())) return response;
        }
    }

    private boolean recovered(OperationRecovery recovery, ProxyResponse challenge, ProxyConnection connection) {
        guard.requireLive(connection);
        RecoveryResult result = recovery.recover(new McpFlow.HttpResponse(
                challenge.statusCode(), challenge.headers(), challenge.body(), true));
        guard.requireLive(connection);
        if (result == RecoveryResult.APPROVAL_REQUIRED || result == RecoveryResult.DENIED) {
            throw new ConnectionAuthException(result);
        }
        if (result != RecoveryResult.RETRY) {
            scannerSession.eventLog().warn("Authentication recovery stopped; returning "
                    + challenge.statusCode() + " to Burp (SSE)");
            return false;
        }
        scannerSession.eventLog().info("Authentication recovery after " + challenge.statusCode()
                + ", retrying SSE request");
        return true;
    }

    private static Operation operation(Map<String, String> incoming, Map<String, String> sessionHeaders,
                                       boolean managedAudit) {
        Map<String, String> baseline = new TreeMap<>(String.CASE_INSENSITIVE_ORDER);
        baseline.putAll(sessionHeaders);
        Map<String, String> headers = new HashMap<>(incoming);
        boolean explicitCredentials = false;
        for (var header : incoming.entrySet()) {
            String name = header.getKey();
            if (!isSessionCredential(name, baseline)) continue;
            if (managedAudit || Objects.equals(header.getValue(), baseline.get(name))) headers.remove(name);
            else explicitCredentials = true;
        }
        return new Operation(Map.copyOf(headers), explicitCredentials);
    }

    private static boolean isSessionCredential(String name, Map<String, String> baseline) {
        if (name.equalsIgnoreCase(McpHeaders.SESSION_ID) || name.equalsIgnoreCase(McpHeaders.PROTOCOL_VERSION)) {
            return false;
        }
        return baseline.containsKey(name) || name.equalsIgnoreCase("Authorization")
                || name.equalsIgnoreCase("Cookie") || name.equalsIgnoreCase("Proxy-Authorization");
    }
}
