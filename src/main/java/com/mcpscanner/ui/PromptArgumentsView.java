package com.mcpscanner.ui;

import com.mcpscanner.ui.detail.DetailLabels;
import com.mcpscanner.ui.detail.DetailSection;
import com.mcpscanner.ui.detail.RowMenu;
import com.mcpscanner.ui.widgets.Placeholders;
import com.mcpscanner.ui.widgets.ThemeColors;
import com.mcpscanner.ui.widgets.UiStyle;
import com.mcpscanner.ui.widgets.WrappingText;

import javax.swing.BorderFactory;
import javax.swing.Box;
import javax.swing.JComponent;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JTextArea;
import java.awt.BorderLayout;
import java.awt.Component;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

final class PromptArgumentsView extends JPanel {

    private static final String NO_ARGUMENTS = "Takes no arguments";
    private static final String HINT =
            "Scans fill each argument with a default string. To edit them, use Send to › Repeater.";
    private static final int GAP = 10;
    private static final int BOX_PADDING = 8;

    private final JLabel summary = DetailLabels.muted("");
    private final PromptArgumentGrid grid = new PromptArgumentGrid();
    private final JTextArea callShape = callShapeBox();
    private final DetailSection callShapeSection = DetailSection.of("Call shape", callShape);
    private final Optional<WrappingText> hint;
    private final WrappingText noArguments = Placeholders.wrapping(NO_ARGUMENTS);

    PromptArgumentsView(InventoryTicks ticks) {
        super(new BorderLayout());
        hint = ticks.ifScanning(() -> Placeholders.wrapping(HINT));
        setOpaque(false);
        Box stack = Box.createVerticalBox();
        for (JComponent part : parts()) {
            part.setAlignmentX(Component.LEFT_ALIGNMENT);
            stack.add(part);
            stack.add(Box.createVerticalStrut(GAP));
        }
        add(stack, BorderLayout.NORTH);
    }

    void show(String promptName, List<PromptArgumentEntry> entries, RowMenu argumentMenu) {
        summary.setText(PromptArgumentsSummary.of(entries));
        grid.show(entries, argumentMenu);
        callShape.setText(PromptCallShape.of(promptName, entries));
        showArgumentParts(!entries.isEmpty());
    }

    boolean takesNoArguments() {
        return noArguments.isVisible();
    }

    String summaryText() {
        return summary.getText();
    }

    String callShapeText() {
        return callShape.getText();
    }

    PromptArgumentGrid grid() {
        return grid;
    }

    private void showArgumentParts(boolean hasArguments) {
        List.of(summary, grid, callShapeSection).forEach(part -> part.setVisible(hasArguments));
        hint.ifPresent(part -> part.setVisible(hasArguments));
        noArguments.setVisible(!hasArguments);
    }

    private List<JComponent> parts() {
        List<JComponent> parts = new ArrayList<>(List.of(summary, grid, callShapeSection));
        hint.ifPresent(parts::add);
        parts.add(noArguments);
        return parts;
    }

    private static JTextArea callShapeBox() {
        JTextArea box = UiStyle.monospaced(new JTextArea());
        box.setEditable(false);
        box.setBorder(BorderFactory.createCompoundBorder(
                BorderFactory.createLineBorder(ThemeColors.separator()),
                BorderFactory.createEmptyBorder(BOX_PADDING, BOX_PADDING, BOX_PADDING, BOX_PADDING)));
        return box;
    }
}
