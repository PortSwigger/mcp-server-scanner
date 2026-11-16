package com.mcpscanner.ui;

import com.mcpscanner.logging.McpEventLog;
import com.mcpscanner.mcp.McpToolDefinition;
import com.mcpscanner.scan.ScanMode;
import com.mcpscanner.scan.request.GeneratedScan;
import com.mcpscanner.scan.request.RequestFamily;
import com.mcpscanner.testutil.SwingTree;
import com.mcpscanner.ui.widgets.WarningBanner;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;

import java.util.Arrays;
import java.util.List;

import static com.mcpscanner.ui.McpScannerTabFixture.flushEdt;
import static com.mcpscanner.ui.McpScannerTabFixture.inventory;
import static com.mcpscanner.ui.McpScannerTabFixture.onEdt;
import static com.mcpscanner.ui.McpScannerTabFixture.scanButton;
import static com.mcpscanner.ui.McpScannerTabFixture.statusText;
import static java.time.Duration.ofSeconds;
import static org.assertj.core.api.Assertions.assertThat;
import static org.awaitility.Awaitility.await;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

class ScanBarRequestsAndPausedTasksTest {

    private static final McpToolDefinition UNTICKED = new McpToolDefinition("search", "Search", "{}");

    private McpScannerTabFixture fixture;

    @BeforeEach
    void setUp() {
        fixture = new McpScannerTabFixture();
    }

    @Test
    void withNothingTickedScanSendsTheTickedRequestFamiliesAndCountsThem() throws Exception {
        sendOnly(RequestFamily.PING);
        McpScannerTab tab = fixture.connected(inventory(List.of(UNTICKED)));

        onEdt(() -> {
            assertThat(scanButton(tab).isEnabled()).isTrue();
            assertThat(scanButton(tab).getText()).isEqualTo("Scan 1 protocol request");
            scanButton(tab).doClick();
        });

        ArgumentCaptor<GeneratedScan> scan = ArgumentCaptor.forClass(GeneratedScan.class);
        await().atMost(ofSeconds(5)).untilAsserted(() -> verify(fixture.scanLauncher)
                .captureScan(eq(ScanMode.MCP_ONLY), anyString(), scan.capture(), any(), any()));
        assertThat(scan.getValue().messages()).extracting(message -> message.family())
                .containsExactly(RequestFamily.PING);
        await().atMost(ofSeconds(5)).untilAsserted(() -> onEdt(() ->
                assertThat(statusText(tab)).startsWith("Scan started: 1 protocol request")));
    }

    @Test
    void turningOffTheLastRequestFamilyDisablesScan() throws Exception {
        sendOnly(RequestFamily.PING);
        McpScannerTab tab = fixture.connected(inventory(List.of(UNTICKED)));

        onEdt(() -> fixture.generationSettings.setEnabled(RequestFamily.PING, false));
        flushEdt();

        onEdt(() -> {
            assertThat(scanButton(tab).isEnabled()).isFalse();
            assertThat(scanButton(tab).getText()).isEqualTo("Scan");
        });
    }

    @Test
    void pausedBurpTasksRaiseANoticeAndAWarningInBurpScannerMode() throws Exception {
        when(fixture.scanLauncher.waitsForPausedTasks(ScanMode.MCP_AND_BURP)).thenReturn(true);
        McpScannerTab tab = fixture.connected(inventory(List.of(UNTICKED)));
        onEdt(() -> assertThat(notice(tab).isVisible()).isFalse());

        chooseMode(ScanMode.MCP_AND_BURP);

        onEdt(() -> {
            assertThat(notice(tab).isVisible()).isTrue();
            assertThat(notice(tab).actionButton().getText()).isEqualTo(PausedTasksNotice.RESUME);
        });
        assertThat(fixture.eventLog.snapshot()).anySatisfy(entry -> {
            assertThat(entry.level()).isEqualTo(McpEventLog.Level.WARN);
            assertThat(entry.message()).isEqualTo(PausedTasksNotice.MESSAGE);
        });
    }

    @Test
    void resumingBurpTasksFromTheNoticeResumesThemAndHidesIt() throws Exception {
        when(fixture.scanLauncher.waitsForPausedTasks(ScanMode.MCP_AND_BURP)).thenReturn(true);
        McpScannerTab tab = fixture.connected(inventory(List.of(UNTICKED)));
        chooseMode(ScanMode.MCP_AND_BURP);
        when(fixture.scanLauncher.waitsForPausedTasks(ScanMode.MCP_AND_BURP)).thenReturn(false);

        onEdt(() -> notice(tab).actionButton().doClick());

        verify(fixture.scanLauncher).resumePausedTasks(ScanMode.MCP_AND_BURP);
        onEdt(() -> assertThat(notice(tab).isVisible()).isFalse());
        assertThat(fixture.eventLog.snapshot()).anySatisfy(entry ->
                assertThat(entry.message()).isEqualTo(PausedTasksNotice.RESUMED));
    }

    @Test
    void aBurpScanStartedWhileTasksArePausedSaysItIsQueued() throws Exception {
        sendOnly(RequestFamily.PING);
        when(fixture.scanLauncher.waitsForPausedTasks(ScanMode.MCP_AND_BURP)).thenReturn(true);
        McpScannerTab tab = fixture.connected(inventory(List.of(UNTICKED)));
        chooseMode(ScanMode.MCP_AND_BURP);

        onEdt(() -> scanButton(tab).doClick());

        await().atMost(ofSeconds(5)).untilAsserted(() -> onEdt(() -> assertThat(statusText(tab))
                .startsWith("Scan queued: 1 protocol request")
                .contains("Burp task execution is paused")));
    }

    private void sendOnly(RequestFamily kept) {
        Arrays.stream(RequestFamily.values())
                .forEach(family -> fixture.generationSettings.setEnabled(family, family == kept));
    }

    private void chooseMode(ScanMode mode) throws Exception {
        fixture.scanModeSetting.select(mode);
        flushEdt();
    }

    private static WarningBanner notice(McpScannerTab tab) {
        return SwingTree.descendants(tab).stream()
                .filter(component -> component instanceof WarningBanner banner
                        && banner.message().equals(PausedTasksNotice.MESSAGE))
                .map(WarningBanner.class::cast)
                .findFirst().orElseThrow();
    }
}
