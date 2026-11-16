package com.mcpscanner.checks.catalog.crossclientresponseleak;

import burp.api.montoya.scanner.audit.issues.AuditIssueConfidence;
import burp.api.montoya.scanner.audit.issues.AuditIssueSeverity;
import com.mcpscanner.checks.api.CheckDescriptor;
import com.mcpscanner.checks.api.CheckKind;
import com.mcpscanner.checks.issue.Cwe;

import java.util.List;

final class CrossClientResponseLeakDescriptor {

    static final CheckDescriptor DESCRIPTOR = new CheckDescriptor(
            "cross-client-response-leak",
            "MCP cross-client response leak",
            "Opens several independent MCP client sessions, sends the same captured tool call from all of them at "
                    + "once with the same JSON-RPC id and a unique marker in an argument the server echoes, and "
                    + "reports when one client receives another client's reply while that client loses its own, "
                    + "and the crossing stops once each client uses a distinct id.",
            CheckKind.HOST,
            AuditIssueSeverity.HIGH,
            AuditIssueConfidence.FIRM,
            true,
            List.of(
                    "https://modelcontextprotocol.io/specification/2025-11-25/basic/transports#streamable-http"),
            "Every MCP client numbers its own JSON-RPC requests, usually from zero, so independent clients send "
                    + "the same ids. A server that routes replies by request id across clients, for example by "
                    + "sharing one transport or protocol instance between connections, can deliver one client's "
                    + "result to another. Tool results often carry private data, so the receiving client learns "
                    + "what the other client asked for and was told. Each same-id round was attempted up to "
                    + "three times and counted as crossed if any attempt crossed; each distinct-id round needed "
                    + "three clean attempts. If a server shared state intermittently, crossing in each attempt "
                    + "with probability p whatever the id, a round would cross with q = 1-(1-p)^3, and a false "
                    + "report would need three crossed same-id rounds and three clean distinct-id rounds: "
                    + "probability q^3(1-q)^3, at most 1/64 (about 1.6%, at q = 0.5, p of about 0.21) per "
                    + "trial, assuming attempts are independent.",
            List.of(new Cwe(488, "Exposure of Data Element to Wrong Session"),
                    new Cwe(362, "Concurrent Execution using Shared Resource with Improper Synchronization "
                            + "('Race Condition')")));

    private CrossClientResponseLeakDescriptor() {
    }
}
