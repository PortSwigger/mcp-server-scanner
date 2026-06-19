package com.mcpscanner.ui;

import com.mcpscanner.logging.McpEventLog;
import org.junit.jupiter.api.Test;

import javax.swing.SwingUtilities;

import static java.time.Duration.ofMillis;
import static java.time.Duration.ofSeconds;
import static org.assertj.core.api.Assertions.assertThat;
import static org.awaitility.Awaitility.await;

class LoggerPanelTest {

    @Test
    void formatsEntryWithTimestampLevelAndMessage() throws Exception {
        McpEventLog log = new McpEventLog(null);
        LoggerPanel panel = new LoggerPanel(log);

        log.info("hello world");

        await().atMost(ofSeconds(2)).until(() -> panel.textAreaForTest().getText().contains("hello world"));
        SwingUtilities.invokeAndWait(() -> {});

        String text = panel.textAreaForTest().getText();
        assertThat(text).matches("\\d{2}:\\d{2}:\\d{2} {2}INFO {2}hello world\\R");
    }

    @Test
    void replaysExistingEntriesOnConstruction() throws Exception {
        McpEventLog log = new McpEventLog(null);
        log.info("earlier");

        LoggerPanel panel = new LoggerPanel(log);
        SwingUtilities.invokeAndWait(() -> {});

        assertThat(panel.textAreaForTest().getText()).contains("earlier");
    }

}
