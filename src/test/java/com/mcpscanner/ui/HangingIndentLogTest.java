package com.mcpscanner.ui;

import org.junit.jupiter.api.Test;

import javax.swing.JScrollPane;
import javax.swing.SwingUtilities;
import javax.swing.text.BadLocationException;
import java.awt.geom.Rectangle2D;
import java.util.concurrent.atomic.AtomicReference;

import static org.assertj.core.api.Assertions.assertThat;

class HangingIndentLogTest {

    private static final String PREFIX = "10:07:04  WARN   ";
    private static final String MESSAGE = "PRM fetch failed for ";
    private static final String URL = "https://example.test/.well-known/oauth-protected-resource/"
            + "a".repeat(200);

    @Test
    void anUnbrokenUrlWrapsWithinTheViewportInsteadOfWideningThePane() throws Exception {
        AtomicReference<String> failure = new AtomicReference<>();
        SwingUtilities.invokeAndWait(() -> {
            HangingIndentLog log = new HangingIndentLog(PREFIX.length());
            JScrollPane scroll = new JScrollPane(log);
            log.replaceAll(PREFIX + MESSAGE + URL + "\n");
            layOut(scroll, 300);

            if (log.getWidth() > scroll.getViewport().getWidth()) {
                failure.set("pane wider than viewport: " + log.getWidth());
            } else if (scroll.getHorizontalScrollBar().isVisible()) {
                failure.set("horizontal scrollbar shown");
            } else if (!wraps(log, (PREFIX + MESSAGE).length())) {
                failure.set("url not wrapped");
            }
        });
        assertThat(failure.get()).isNull();
    }

    @Test
    void reWrapsWhenTheViewportGrows() throws Exception {
        AtomicReference<int[]> heights = new AtomicReference<>();
        SwingUtilities.invokeAndWait(() -> {
            HangingIndentLog log = new HangingIndentLog(PREFIX.length());
            JScrollPane scroll = new JScrollPane(log);
            log.replaceAll(PREFIX + URL + "\n");
            layOut(scroll, 300);
            int narrow = log.getPreferredSize().height;
            layOut(scroll, 3000);
            heights.set(new int[] {narrow, log.getPreferredSize().height});
        });
        assertThat(heights.get()[1]).isLessThan(heights.get()[0]);
    }

    @Test
    void removingLinesKeepsTheRest() throws Exception {
        AtomicReference<String> text = new AtomicReference<>();
        SwingUtilities.invokeAndWait(() -> {
            HangingIndentLog log = new HangingIndentLog(PREFIX.length());
            log.replaceAll("first\nsecond\n");
            log.appendLine("third\nfourth\n");
            log.removeLines(1, 2);
            text.set(log.getText());
        });
        assertThat(text.get().lines()).containsExactly("first", "fourth");
    }

    private static void layOut(JScrollPane scroll, int width) {
        scroll.setSize(width, 200);
        scroll.doLayout();
        scroll.getViewport().doLayout();
        scroll.doLayout();
        scroll.getViewport().doLayout();
    }

    private static boolean wraps(HangingIndentLog log, int urlStart) {
        try {
            Rectangle2D urlBegins = log.modelToView2D(urlStart);
            Rectangle2D urlEnds = log.modelToView2D(log.getDocument().getLength() - 2);
            return urlEnds.getY() > urlBegins.getY();
        } catch (BadLocationException impossible) {
            throw new IllegalStateException(impossible);
        }
    }
}
