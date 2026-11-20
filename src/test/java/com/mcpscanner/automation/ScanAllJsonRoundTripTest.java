package com.mcpscanner.automation;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.mcpscanner.mcp.McpObjectMapper;
import org.junit.jupiter.api.Test;

import java.net.URI;
import java.util.List;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;

class ScanAllJsonRoundTripTest {

    private final ObjectMapper harnessJson = new ObjectMapper();

    @Test
    void theHarnessReadsALaunchedScanWithAndWithoutACatalogLimit() throws Exception {
        assertThat(harnessJson.readValue("{\"requests\":51,\"catalogLimit\":\"tools 124 -> 50\"}", LaunchedScan.class))
                .isEqualTo(new LaunchedScan(51, "tools 124 -> 50"));
        assertThat(harnessJson.readValue("{\"requests\":19}", LaunchedScan.class)).isEqualTo(new LaunchedScan(19));
    }

    @Test
    void aScanAllCommandKeepsItsCatalogLimitAcrossTheWire() throws Exception {
        ScanAllCommand sent = new ScanAllCommand("http://127.0.0.1:1/mcp", null, null, null, null, null, true, null, 100);

        ScanAllCommand received = harnessJson.readValue(harnessJson.writeValueAsString(sent), ScanAllCommand.class);

        assertThat(received.maxCatalogItems()).isEqualTo(100);
        assertThat(received.divertBuiltInChecks()).isTrue();
    }

    @Test
    void aScanAllCommandKeepsItsSignedInSessionAcrossTheWire() throws Exception {
        SignedInSessionCommand session = new SignedInSessionCommand(
                List.of(new CommandCookie("127.0.0.1", "/", "mcp_test_session", "s3ss10n")), true,
                new CommandScannerClient(URI.create("http://127.0.0.1:4100"),
                        URI.create("http://127.0.0.1:4100/authorize"), URI.create("http://127.0.0.1:4100/register"),
                        "mcp-server-scanner_AbCd", "MCP Server Scanner", URI.create("http://127.0.0.1:47390/callback"),
                        Set.of("mcp:tools"), "mcp-server-scanner"));
        ScanAllCommand sent = new ScanAllCommand("http://127.0.0.1:1/mcp", null, null, null, null, null, true, null,
                null, session);

        ScanAllCommand received = McpObjectMapper.INSTANCE.readValue(harnessJson.writeValueAsString(sent),
                ScanAllCommand.class);

        assertThat(received.signedInSession()).isEqualTo(session);
    }

    @Test
    void aScanAllCommandKeepsAHandedOverOAuthSessionAcrossTheWire() throws Exception {
        ScanAllCommand sent = new ScanAllCommand("http://127.0.0.1:1/mcp", null,
                CommandAuth.handedOver(HandedOverOAuthStrategyTest.SESSION), null, null, null, true, null);

        ScanAllCommand received = McpObjectMapper.INSTANCE.readValue(harnessJson.writeValueAsString(sent),
                ScanAllCommand.class);

        assertThat(received.auth()).isEqualTo(sent.auth());
    }

    @Test
    void aScanAllCommandWithoutASignedInSessionCarriesNone() throws Exception {
        ScanAllCommand received = McpObjectMapper.INSTANCE.readValue("{\"endpoint\":\"http://127.0.0.1:1/mcp\"}",
                ScanAllCommand.class);

        assertThat(received.signedInSession()).isEqualTo(SignedInSessionCommand.NONE);
    }
}
