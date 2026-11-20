package com.mcpscanner.proxy;

import com.mcpscanner.mcp.FramedOperation;
import com.mcpscanner.mcp.ScannerSentinels;
import org.junit.jupiter.api.Test;

import java.util.HashMap;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

class OperationHeaderFramingTest {

    private static final Map<String, String> FRAMED = Map.of("Mcp-Method", "tools/call", "Mcp-Name", "slow",
            "MCP-Protocol-Version", "2026-07-28");

    private final OperationHeaderFraming framing = new OperationHeaderFraming();

    @Test
    void aHeaderMatchingTheBodyIsFramedFromTheBody() {
        assertThat(framing.frame(Map.of("X-Custom", "kept"), FRAMED, scannerRequest(FRAMED)))
                .containsAllEntriesOf(FRAMED).containsEntry("X-Custom", "kept");
    }

    @Test
    void aMissingHeaderIsFramedFromTheBody() {
        assertThat(framing.frame(Map.of(), FRAMED, scannerRequest(Map.of()))).containsAllEntriesOf(FRAMED);
    }

    @Test
    void aFuzzedOperationHeaderReachesTheServerAsSent() {
        Map<String, String> headers = framing.frame(Map.of(), FRAMED, scannerRequest(Map.of(
                "mcp-name", "slow;payload", "Mcp-Method", "tools/call'payload", "MCP-Protocol-Version", "payload")));

        assertThat(headers).containsEntry("mcp-name", "slow;payload")
                .containsEntry("Mcp-Method", "tools/call'payload")
                .containsEntry("MCP-Protocol-Version", "payload")
                .doesNotContainKey("Mcp-Name");
    }

    @Test
    void aHeaderLeftStaleByABodyPayloadIsFramedFromTheBodyWithoutAnEarlierRequest() {
        Map<String, String> bodyFuzzed = Map.of("Mcp-Method", "tools/call", "Mcp-Name", "slow'payload",
                "MCP-Protocol-Version", "2026-07-28");

        assertThat(framing.frame(Map.of(), bodyFuzzed, scannerRequest(FRAMED))).containsEntry("Mcp-Name", "slow'payload");
    }

    @Test
    void aRequestTheScannerDidNotFrameKeepsItsOperationHeadersAsTyped() {
        Map<String, String> typed = Map.of("mcp-name", "edited", "Mcp-Method", "tools/call",
                "MCP-Protocol-Version", "2025-06-18");

        assertThat(framing.frame(Map.of(), FRAMED, typed)).containsAllEntriesOf(typed)
                .doesNotContainKey("Mcp-Name").doesNotContainValue("2026-07-28");
    }

    @Test
    void aRequestTheScannerDidNotFrameGetsAnOperationHeaderItLacksFromTheBody() {
        assertThat(framing.frame(Map.of(), FRAMED, Map.of("Mcp-Name", "edited")))
                .containsEntry("Mcp-Name", "edited")
                .containsEntry("Mcp-Method", "tools/call")
                .containsEntry("MCP-Protocol-Version", "2026-07-28");
    }

    @Test
    void aRequestTheScannerDidNotFrameStillGetsItsParamHeadersFromTheBody() {
        assertThat(framing.frame(Map.of("Mcp-Param-Region", "typed"), Map.of("Mcp-Param-Tenant", "acme"),
                Map.of("Mcp-Param-Region", "typed"))).containsEntry("Mcp-Param-Tenant", "acme")
                .doesNotContainKey("Mcp-Param-Region");
    }

    @Test
    void aRequestWhoseFramedOperationSentinelWasFuzzedHasItsOperationHeadersFramedFromTheBody() {
        Map<String, String> incoming = Map.of("Mcp-Name", "stale",
                ScannerSentinels.FRAMED_OPERATION_HEADER, "!!not-base64!!");

        assertThat(framing.frame(Map.of(), FRAMED, incoming)).containsEntry("Mcp-Name", "slow")
                .doesNotContainValue("stale");
    }

    @Test
    void aFuzzedParamHeaderIsStillReplacedByTheBodysValue() {
        Map<String, String> headers = framing.frame(Map.of("MCP-PARAM-REGION", "fuzzed"),
                Map.of("Mcp-Method", "tools/call", "Mcp-Param-Tenant", "acme"),
                scannerRequest(Map.of("MCP-PARAM-REGION", "fuzzed")));

        assertThat(headers).containsEntry("Mcp-Param-Tenant", "acme").doesNotContainKey("MCP-PARAM-REGION");
    }

    @Test
    void anIncomingParamHeaderIsDroppedWhenTheBodyDeclaresNone() {
        assertThat(framing.frame(Map.of("Mcp-Param-Tenant", "stale"), Map.of("Mcp-Method", "prompts/get"),
                Map.of("Mcp-Param-Tenant", "stale"))).doesNotContainKey("Mcp-Param-Tenant");
    }

    private static Map<String, String> scannerRequest(Map<String, String> operationHeaders) {
        Map<String, String> incoming = new HashMap<>(operationHeaders);
        incoming.put(ScannerSentinels.FRAMED_OPERATION_HEADER, FramedOperation.encode(FRAMED));
        return incoming;
    }
}
