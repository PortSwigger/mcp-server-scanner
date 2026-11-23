package com.mcpscanner;

import com.mcpscanner.auth.BearerTokenAuthStrategy;
import com.mcpscanner.client.McpServerConfig;
import com.mcpscanner.client.TransportType;
import com.mcpscanner.mcp.McpToolDefinition;
import com.mcpscanner.testutil.MontoyaTestFactory;
import com.mcpscanner.testutil.StreamingCampaignServer;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Map;
import java.util.TreeMap;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import static org.assertj.core.api.Assertions.assertThat;

class StreamedToolCallScanWiringTest {

    private static final Pattern CHECK_FINISHED =
            Pattern.compile("Scan check: (\\S+) — finished in \\d+ms, (\\d+) requests?");

    @BeforeEach
    void installMontoya() {
        MontoyaTestFactory.install();
    }

    @Test
    void scanThroughBurpGetsTheToolCallRepliesTheServerStreamsAndSendsAsManyProbesAsAgainstAJsonServer()
            throws Exception {
        ScanRun baseline = scanThroughBurp(StreamingCampaignServer.streamingNothing());
        ScanRun streamed = scanThroughBurp(StreamingCampaignServer.streamingOnlyToolCalls());

        assertThat(baseline.requestsPerCheck()).containsKey("file-traversal");
        assertThat(streamed.requestsPerCheck()).isEqualTo(baseline.requestsPerCheck());
        assertThat(streamed.errors()).noneMatch(message -> message.startsWith("Proxy error"))
                .filteredOn(message -> message.contains("bypass Burp")).singleElement().asString()
                .contains("tools/call");
    }

    @Test
    void reconnectingTriesBurpAgainAndWarnsAgainThatStreamedRepliesBypassBurp() throws Exception {
        try (StreamingCampaignServer server = StreamingCampaignServer.streamingOnlyToolCalls();
             WiredExtension extension = WiredExtension.sendingThroughBurp()) {
            McpToolDefinition tool = connect(extension, server).get(0);
            extension.scanTool(tool);
            extension.connection().clientManager().disconnect();
            connect(extension, server);
            extension.scanTool(tool);

            assertThat(extension.burpErrors()).filteredOn(message -> message.contains("bypass Burp")).hasSize(2);
        }
    }

    private static List<McpToolDefinition> connect(WiredExtension extension, StreamingCampaignServer server) {
        BearerTokenAuthStrategy alice = new BearerTokenAuthStrategy(StreamingCampaignServer.ALICE_TOKEN);
        extension.access().authHolder().set(alice);
        return extension.connection().clientManager()
                .connect(new McpServerConfig(server.endpoint(), TransportType.STREAMABLE_HTTP, alice)).tools();
    }

    private static ScanRun scanThroughBurp(StreamingCampaignServer server) throws Exception {
        try (server; WiredExtension extension = WiredExtension.sendingThroughBurp()) {
            extension.scanTool(connect(extension, server).get(0));
            return new ScanRun(extension.everyLogLineOnceTheScanFinished(), extension.burpErrors());
        }
    }

    private record ScanRun(List<String> output, List<String> errors) {

        Map<String, Integer> requestsPerCheck() {
            Map<String, Integer> counts = new TreeMap<>();
            for (String message : output) {
                Matcher finished = CHECK_FINISHED.matcher(message);
                if (finished.find()) {
                    counts.merge(finished.group(1), Integer.parseInt(finished.group(2)), Integer::sum);
                }
            }
            return counts;
        }
    }
}
