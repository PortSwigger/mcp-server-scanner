package com.mcpscanner.ui.widgets;

import com.mcpscanner.testutil.SwingTree;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;

import javax.swing.JComponent;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.RepaintManager;
import javax.swing.SwingUtilities;
import java.util.ArrayList;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

class WrappingTextTest {

    private final RepaintManager original = RepaintManager.currentManager((JComponent) null);

    @AfterEach
    void restore() {
        RepaintManager.setCurrentManager(original);
    }

    @Test
    void aWidthChangeRevalidatesOnlyAfterTheCurrentLayoutPassSoTheNewHeightIsApplied() throws Exception {
        List<JComponent> invalidated = new ArrayList<>();
        WrappingText text = new WrappingText("Sends no credentials if the server allows it.");
        List<Integer> duringLayout = new ArrayList<>();
        SwingUtilities.invokeAndWait(() -> {
            RepaintManager.setCurrentManager(new RecordingRepaintManager(invalidated));
            new JPanel().add(text);
            text.setBounds(0, 0, 200, 20);
            duringLayout.add(invalidated.size());
        });

        SwingUtilities.invokeAndWait(() -> { });

        assertThat(duringLayout).containsExactly(0);
        assertThat(invalidated).contains(text);
    }

    @Test
    void settingTextNeverScrollsTheEnclosingViewport() throws Exception {
        WrappingText text = new WrappingText("first line\n".repeat(40));
        JScrollPane scrollPane = new JScrollPane(text);
        List<Integer> viewportTops = new ArrayList<>();
        SwingUtilities.invokeAndWait(() -> {
            scrollPane.setSize(200, 60);
            text.updateUI();
            SwingTree.layOut(scrollPane);
            text.setText("second text\n".repeat(40));
        });

        SwingUtilities.invokeAndWait(() -> viewportTops.add(scrollPane.getViewport().getViewPosition().y));

        assertThat(viewportTops).containsExactly(0);
    }

    private static final class RecordingRepaintManager extends RepaintManager {
        private final List<JComponent> invalidated;

        private RecordingRepaintManager(List<JComponent> invalidated) {
            this.invalidated = invalidated;
        }

        @Override
        public synchronized void addInvalidComponent(JComponent component) {
            invalidated.add(component);
        }
    }
}
