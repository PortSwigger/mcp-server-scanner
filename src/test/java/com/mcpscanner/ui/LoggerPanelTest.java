package com.mcpscanner.ui;

import com.mcpscanner.logging.McpEventLog;
import com.mcpscanner.testutil.SwingTree;
import org.junit.jupiter.api.Test;

import javax.swing.JButton;
import javax.swing.JComboBox;
import javax.swing.JTextPane;
import javax.swing.text.Element;
import javax.swing.text.StyleConstants;
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

        await().atMost(ofSeconds(2)).until(() -> textArea(panel).getText().contains("hello world"));
        SwingUtilities.invokeAndWait(() -> {});

        String text = textArea(panel).getText();
        assertThat(text).matches("\\d{2}:\\d{2}:\\d{2} {2}INFO {3}hello world\\R");
    }

    @Test
    void messagesStartInTheSameColumnWhateverTheirLevel() throws Exception {
        McpEventLog log = new McpEventLog(null);
        log.info("first");
        log.warn("second");
        log.error("third");
        LoggerPanel panel = new LoggerPanel(log);
        SwingUtilities.invokeAndWait(() -> {});

        assertThat(textArea(panel).getText().lines().map(line -> line.substring(LogLine.PREFIX_COLUMNS)))
                .containsExactly("first", "second", "third");
    }

    @Test
    void wrappedLinesHangUnderTheMessageNotTheTimestamp() throws Exception {
        McpEventLog log = new McpEventLog(null);
        log.info("a long message that will wrap in a narrow drawer");
        LoggerPanel panel = new LoggerPanel(log);
        SwingUtilities.invokeAndWait(() -> {});

        JTextPane pane = textArea(panel);
        Element paragraph = pane.getStyledDocument().getParagraphElement(0);
        float left = StyleConstants.getLeftIndent(paragraph.getAttributes());
        float first = StyleConstants.getFirstLineIndent(paragraph.getAttributes());
        int prefixWidth = pane.getFontMetrics(pane.getFont()).charWidth('0') * LogLine.PREFIX_COLUMNS;
        assertThat(left).isEqualTo((float) prefixWidth);
        assertThat(first).isEqualTo((float) -prefixWidth);
    }

    @Test
    void appendedLinesHangToo() throws Exception {
        McpEventLog log = new McpEventLog(null);
        LoggerPanel panel = new LoggerPanel(log);

        log.info("first");
        log.info("second");
        await().atMost(ofSeconds(2)).until(() -> textArea(panel).getText().contains("second"));
        SwingUtilities.invokeAndWait(() -> {});

        JTextPane pane = textArea(panel);
        int secondLine = pane.getText().indexOf("second");
        Element paragraph = pane.getStyledDocument().getParagraphElement(secondLine);
        assertThat(StyleConstants.getFirstLineIndent(paragraph.getAttributes())).isNegative();
    }

    @Test
    void replaysExistingEntriesOnConstruction() throws Exception {
        McpEventLog log = new McpEventLog(null);
        log.info("earlier");

        LoggerPanel panel = new LoggerPanel(log);
        SwingUtilities.invokeAndWait(() -> {});

        assertThat(textArea(panel).getText()).contains("earlier");
    }

    @Test
    void levelFilterShowsOnlyMatchingEntriesAndAllRestoresThem() throws Exception {
        McpEventLog log = new McpEventLog(null);
        log.info("routine");
        log.warn("careful");
        log.error("broken");
        LoggerPanel panel = new LoggerPanel(log);
        SwingUtilities.invokeAndWait(() -> {});

        levelFilter(panel).setSelectedItem(LogLevelFilter.ERRORS);

        assertThat(textArea(panel).getText()).contains("broken").doesNotContain("routine", "careful");

        levelFilter(panel).setSelectedItem(LogLevelFilter.ALL);

        assertThat(textArea(panel).getText()).contains("routine", "careful", "broken");
    }

    @Test
    void newEntriesHiddenByTheFilterAreKeptForLater() throws Exception {
        McpEventLog log = new McpEventLog(null);
        LoggerPanel panel = new LoggerPanel(log);
        levelFilter(panel).setSelectedItem(LogLevelFilter.ERRORS);

        log.info("routine");
        log.error("broken");
        await().atMost(ofSeconds(2)).until(() -> textArea(panel).getText().contains("broken"));
        SwingUtilities.invokeAndWait(() -> {});

        assertThat(textArea(panel).getText()).doesNotContain("routine");
        levelFilter(panel).setSelectedItem(LogLevelFilter.INFO);
        assertThat(textArea(panel).getText()).contains("routine").doesNotContain("broken");
    }

    @Test
    void aFullBufferDropsItsOldestLineAsNewOnesArrive() throws Exception {
        McpEventLog log = new McpEventLog(null);
        LoggerPanel panel = new LoggerPanel(log);

        for (int line = 0; line <= 1000; line++) {
            log.info("line " + line);
        }
        await().atMost(ofSeconds(5)).until(() -> textArea(panel).getText().contains("line 1000"));
        SwingUtilities.invokeAndWait(() -> {});

        assertThat(textArea(panel).getText().lines()).hasSize(1000)
                .first().asString().endsWith("line 1");
    }

    @Test
    void connectLinesSurviveTheDebugVolumeOfASeventeenCheckScan() throws Exception {
        McpEventLog log = new McpEventLog(null);
        LoggerPanel panel = new LoggerPanel(log);

        log.info("Connected to MCP server");
        log.info("Opening browser for sign-in");
        log.info("Signed-in consent probes not run: opt-in is off");
        for (int invocation = 0; invocation < 2_327; invocation++) {
            log.debug("check " + invocation % 17 + " started");
            log.debug("check " + invocation % 17 + " finished");
        }
        log.kept("Scan finished");
        awaitLine(panel, "Scan finished");

        assertThat(textArea(panel).getText().lines()).hasSize(4).anySatisfy(line -> assertThat(line)
                .endsWith("Connected to MCP server")).anySatisfy(line -> assertThat(line)
                .endsWith("Opening browser for sign-in")).anySatisfy(line -> assertThat(line)
                .endsWith("Signed-in consent probes not run: opt-in is off"));
    }

    @Test
    void anEvictedLineInTheMiddleOfTheViewLeavesTheView() throws Exception {
        McpEventLog log = new McpEventLog(null);
        LoggerPanel panel = new LoggerPanel(log);

        log.kept("Scan started");
        for (int line = 0; line <= 999; line++) {
            log.info("line " + line);
        }
        awaitLine(panel, "line 999");

        assertThat(textArea(panel).getText().lines()).hasSize(1000)
                .first().asString().endsWith("Scan started");
        assertThat(textArea(panel).getText().lines()).element(1).asString().endsWith("line 1");
    }

    @Test
    void anEvictedMultiLineMessageLeavesTheViewWhole() throws Exception {
        McpEventLog log = new McpEventLog(null);
        LoggerPanel panel = new LoggerPanel(log);

        log.kept("Scan started");
        log.warn("metadata fetch failed: Unexpected character\n at [Source: REDACTED; line: 1]");
        for (int line = 0; line <= 999; line++) {
            log.info("line " + line);
        }
        awaitLine(panel, "line 999");

        assertThat(textArea(panel).getText()).doesNotContain("[Source");
        assertThat(textArea(panel).getText().lines()).hasSize(1000)
                .first().asString().endsWith("Scan started");
        assertThat(textArea(panel).getText().lines()).element(1).asString().endsWith("line 1");
    }

    @Test
    void theDebugViewDropsTheDebugLinesThatAreEvicted() throws Exception {
        McpEventLog log = new McpEventLog(null);
        LoggerPanel panel = new LoggerPanel(log);
        levelFilter(panel).setSelectedItem(LogLevelFilter.DEBUG);

        log.info("Connected to MCP server");
        for (int line = 0; line < 1_500; line++) {
            log.debug("decision " + line);
        }
        awaitLine(panel, "decision 1499");

        assertThat(textArea(panel).getText().lines()).hasSize(999)
                .first().asString().endsWith("decision 501");
        levelFilter(panel).setSelectedItem(LogLevelFilter.ALL);
        assertThat(textArea(panel).getText()).contains("Connected to MCP server");
    }

    private static void awaitLine(LoggerPanel panel, String lastMessage) throws Exception {
        await().atMost(ofSeconds(10)).until(() -> {
            String[] text = new String[1];
            SwingUtilities.invokeAndWait(() -> text[0] = textArea(panel).getText());
            return text[0].contains(lastMessage);
        });
    }

    @Test
    void clearEmptiesTheLogForEveryFilter() throws Exception {
        McpEventLog log = new McpEventLog(null);
        log.error("broken");
        LoggerPanel panel = new LoggerPanel(log);
        SwingUtilities.invokeAndWait(() -> {});

        clearButton(panel).doClick();
        levelFilter(panel).setSelectedItem(LogLevelFilter.ERRORS);

        assertThat(textArea(panel).getText()).isEmpty();
    }

    private static JTextPane textArea(LoggerPanel panel) {
        return only(panel, JTextPane.class);
    }

    private static JComboBox<?> levelFilter(LoggerPanel panel) {
        return only(panel, JComboBox.class);
    }

    private static JButton clearButton(LoggerPanel panel) {
        return SwingTree.descendants(panel).stream()
                .filter(c -> c instanceof JButton button && "Clear".equals(button.getText()))
                .map(JButton.class::cast).findFirst().orElseThrow();
    }

    private static <T> T only(LoggerPanel panel, Class<T> type) {
        return SwingTree.descendants(panel).stream().filter(type::isInstance).map(type::cast).findFirst().orElseThrow();
    }

    @Test
    void disposedPanelStopsListeningToTheLog() throws Exception {
        McpEventLog log = new McpEventLog(null);
        LoggerPanel panel = new LoggerPanel(log);
        java.util.concurrent.CountDownLatch delivered = new java.util.concurrent.CountDownLatch(1);

        panel.dispose();
        log.info("after dispose");
        log.subscribe(entry -> delivered.countDown());
        log.info("sentinel");

        assertThat(delivered.await(2, java.util.concurrent.TimeUnit.SECONDS)).isTrue();
        SwingUtilities.invokeAndWait(() -> {});
        assertThat(textArea(panel).getText()).doesNotContain("after dispose");
    }
}
