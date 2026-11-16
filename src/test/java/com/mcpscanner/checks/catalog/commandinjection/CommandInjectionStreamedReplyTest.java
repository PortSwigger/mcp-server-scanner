package com.mcpscanner.checks.catalog.commandinjection;

import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.scanner.audit.issues.AuditIssue;
import com.mcpscanner.checks.api.SettlingLateIssues;
import com.mcpscanner.checks.shared.collaborator.CollaboratorWatch;
import com.mcpscanner.checks.shared.collaborator.TestWatches;
import com.mcpscanner.logging.McpEventLog;
import com.mcpscanner.mcp.BurpNativeJsonRpcFields;
import com.mcpscanner.testutil.MontoyaTestFactory;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;

class CommandInjectionStreamedReplyTest {

    private static final ArithmeticCanary CANARY = new ArithmeticCanary(123_456_789L, 987_654_321L);

    private final McpEventLog eventLog = new McpEventLog(null);

    @BeforeEach
    void installMontoya() {
        MontoyaTestFactory.install();
    }

    @Test
    void findsCommandInjectionInStreamedToolCallRepliesBurpRefuses() throws Exception {
        SimulatedToolServer tools = new SimulatedToolServer("ping_host", "host", ToolBehaviours.shellCommandLine())
                .replyingWithSse();
        try (LoopbackStreamingServer server = new LoopbackStreamingServer(tools)) {
            tools.atEndpoint(server.endpoint());
            HttpRequestResponse base = tools.baseline();

            List<AuditIssue> issues = audit(base, tools);

            assertThat(issues).extracting(AuditIssue::name).containsExactly("MCP OS command injection");
        }
    }

    @Test
    void runsTheInBandProbesWhenTheBaselineItselfWasRefusedByBurp() throws Exception {
        SimulatedToolServer tools = new SimulatedToolServer("ping_host", "host", ToolBehaviours.shellCommandLine())
                .replyingWithSse();
        try (LoopbackStreamingServer server = new LoopbackStreamingServer(tools)) {
            tools.atEndpoint(server.endpoint());
            HttpRequestResponse unansweredBase = HttpRequestResponse.httpRequestResponse(tools.baseline().request(), null);

            audit(unansweredBase, tools);

            assertThat(server.requestBodies()).hasSizeGreaterThan(1);
            assertThat(skipLines()).noneMatch(line -> line.contains("the baseline got no JSON-RPC reply"));
        }
    }

    private List<AuditIssue> audit(HttpRequestResponse base, SimulatedToolServer tools) {
        CollaboratorWatch watch = TestWatches.immediate(Optional::empty);
        SettlingLateIssues settling = new SettlingLateIssues(watch);
        CommandInjectionCheck check = new CommandInjectionCheck(() -> CANARY, watch, settling,
                BurpNativeJsonRpcFields.PRESENT, eventLog);
        return check.audit(base, tools.argumentField(base), StreamingRefusingBurp.http());
    }

    private List<String> skipLines() {
        return eventLog.snapshot().stream().map(McpEventLog.LogEntry::message).toList();
    }
}
