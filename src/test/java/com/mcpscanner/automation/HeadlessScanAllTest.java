package com.mcpscanner.automation;

import com.fasterxml.jackson.databind.JsonNode;
import com.mcpscanner.access.WriteReplayConfirmations;
import com.mcpscanner.auth.CurrentAuthHolder;
import com.mcpscanner.identity.IdentityRegistry;
import com.mcpscanner.identity.IdentityStore;
import com.mcpscanner.logging.McpEventLog;
import com.mcpscanner.testutil.InMemoryPersistedObject;
import com.mcpscanner.client.ConnectResult;
import com.mcpscanner.client.McpClientManager;
import com.mcpscanner.client.McpScannerSession;
import com.mcpscanner.client.TransportType;
import com.mcpscanner.mcp.McpToolDefinition;
import com.mcpscanner.mcp.ServerMetadata;
import com.mcpscanner.scan.McpScanLauncher;
import com.mcpscanner.scan.ScanMode;
import com.mcpscanner.scan.request.GeneratedScan;
import com.mcpscanner.scan.request.McpMessage;
import com.mcpscanner.scan.request.RequestFamily;
import com.mcpscanner.testutil.MontoyaTestFactory;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;

import java.util.List;
import java.util.Map;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

class HeadlessScanAllTest {

    private static final String ENDPOINT = "http://target/mcp";
    private static final McpToolDefinition GET_DOCUMENT = new McpToolDefinition("get_document", "",
            "{\"type\":\"object\",\"properties\":{\"doc_id\":{\"type\":\"string\"}},\"required\":[\"doc_id\"]}");

    private static final CommandIdentities ALICE_OWNS_A_DOCUMENT = new CommandIdentities(
            new CommandUser("alice", null, null, null, Map.of("doc_id", "d-alice-0001")), List.of(),
            Set.of("get_document"), List.of(), List.of());

    private final McpClientManager clientManager = mock(McpClientManager.class);
    private final McpScannerSession session = mock(McpScannerSession.class);
    private final McpScanLauncher launcher = mock(McpScanLauncher.class);
    private final IdentityRegistry registry = new IdentityRegistry(
            new IdentityStore(InMemoryPersistedObject.configStore(), McpEventLog.noop()));
    private final WriteReplayConfirmations confirmations = new WriteReplayConfirmations();
    private final HeadlessScanAll scanAll = new HeadlessScanAll(new HeadlessConnection(clientManager, useBurp -> { },
            new IdentityHandover(registry, confirmations, (item, expectation) -> { }, seeds -> { }), new CurrentAuthHolder(),
            mock(SignedInSessionSeed.class)),
            mock(CommandSettings.class), family -> true, launcher, mock(LaunchedAudit.class),
            tool -> registry.primaryUser().ownedValues().ownerArguments().all());

    @BeforeEach
    void setUp() {
        MontoyaTestFactory.install();
        when(clientManager.connect(any())).thenAnswer(connecting -> {
            confirmations.clear();
            return new ConnectResult(List.of(GET_DOCUMENT), List.of(), List.of(), List.of(),
                    new ServerMetadata(Map.of(), null, Map.of("tools", Map.of())));
        });
        when(clientManager.scannerSession()).thenReturn(session);
        when(session.negotiatedProtocolVersion()).thenReturn("2025-06-18");
        when(session.resolvedEndpoint()).thenReturn(ENDPOINT);
    }

    @Test
    void headlessScanAllAlwaysLaunchesABurpAuditWhateverTheTabsScanMode() {
        scanAll.launch(new ScanAllCommand(ENDPOINT, TransportType.AUTO, null, null, null, null, false, null));

        verify(launcher).captureScan(eq(ScanMode.MCP_AND_BURP), anyString(), any(GeneratedScan.class), any(), any());
        verify(launcher, never()).captureScan(eq(ScanMode.MCP_ONLY), anyString(), any(GeneratedScan.class), any(),
                any());
    }

    @Test
    void scanAllCallsToolsWithTheHandedOverConnectAsUsersOwnedObjects() {
        scanAll.launch(new ScanAllCommand(ENDPOINT, null, null, null, null, null, false, ALICE_OWNS_A_DOCUMENT));

        assertThat(launchedToolArguments().path("doc_id").asText()).isEqualTo("d-alice-0001");
    }

    @Test
    void writeConfirmationsOutliveTheResetThatConnectingApplies() {
        scanAll.launch(new ScanAllCommand(ENDPOINT, null, null, null, null, null, false, ALICE_OWNS_A_DOCUMENT));

        assertThat(confirmations.confirmed("get_document")).isTrue();
    }

    @Test
    void aCatalogLimitTrimsTheScannedToolsAndTellsTheCaller() {
        McpToolDefinition listDocuments = new McpToolDefinition("list_documents", "", "{\"type\":\"object\"}");
        when(clientManager.connect(any())).thenReturn(new ConnectResult(List.of(GET_DOCUMENT, listDocuments), List.of(),
                List.of(), List.of(), new ServerMetadata(Map.of(), null, Map.of("tools", Map.of()))));

        LaunchedScan launched = scanAll.launch(new ScanAllCommand(ENDPOINT, null, null, null, null, null, false, null, 1));

        ArgumentCaptor<GeneratedScan> scan = ArgumentCaptor.forClass(GeneratedScan.class);
        verify(launcher).captureScan(any(), anyString(), scan.capture(), any(), any());
        assertThat(scan.getValue().messages()).filteredOn(message -> message.family() == RequestFamily.TOOLS_CALL)
                .hasSize(1);
        assertThat(launched.catalogLimit()).contains("tools 2 -> 1");
    }

    private JsonNode launchedToolArguments() {
        ArgumentCaptor<GeneratedScan> scan = ArgumentCaptor.forClass(GeneratedScan.class);
        verify(launcher).captureScan(any(), anyString(), scan.capture(), any(), any());
        return scan.getValue().messages().stream()
                .filter(message -> message.family() == RequestFamily.TOOLS_CALL)
                .map(McpMessage.class::cast)
                .findFirst().orElseThrow()
                .params().orElseThrow().path("arguments");
    }
}
