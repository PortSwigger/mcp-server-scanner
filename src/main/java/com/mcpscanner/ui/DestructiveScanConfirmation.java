package com.mcpscanner.ui;

import com.mcpscanner.mcp.McpToolDefinition;
import com.mcpscanner.ui.widgets.DialogOwner;

import javax.swing.BorderFactory;
import javax.swing.Box;
import javax.swing.BoxLayout;
import javax.swing.JButton;
import javax.swing.JCheckBox;
import javax.swing.JDialog;
import javax.swing.JList;
import javax.swing.JPanel;
import javax.swing.JRootPane;
import javax.swing.JScrollPane;
import javax.swing.JTextArea;
import javax.swing.KeyStroke;
import javax.swing.WindowConstants;
import java.awt.BorderLayout;
import java.awt.Component;
import java.awt.Dialog;
import java.awt.Dimension;
import java.awt.Font;
import java.awt.FlowLayout;
import java.awt.event.ActionEvent;
import java.awt.event.KeyEvent;
import java.util.List;
import javax.swing.AbstractAction;
import javax.swing.JComponent;
import javax.swing.UIManager;

public final class DestructiveScanConfirmation {

    private static final String SCAN_TITLE = "Enable destructive scanning?";
    private static final String COLLECT_TITLE = "Allow write calls while collecting IDs?";
    private static final String REPLAY_TITLE = "Replay write tools as other users?";
    private static final String LEAD_TEXT_AFTER_INVOKER = " will invoke these tools with attacker-controlled inputs. "
            + "This can modify, create, or delete data on the target — irreversible.";
    private static final String SPEC_CAVEAT =
            "Tool annotations are advisory; the server may have understated risk.";
    private static final int LIST_VISIBLE_ROWS = 6;
    private static final int DIALOG_WIDTH = 700;

    private DestructiveScanConfirmation() {
    }

    static String leadText(String invoker) {
        return invoker + LEAD_TEXT_AFTER_INVOKER;
    }

    static Lines scanLines(List<McpToolDefinition> nonReadOnly, int selectedCount, String invoker) {
        return new Lines(leadText(invoker), DestructiveScanPolicy.countLine(nonReadOnly.size(), selectedCount),
                nonReadOnly.stream().map(DestructiveScanPolicy::formatToolLine).toList(), Purpose.SCAN);
    }

    static Result promptLines(DialogOwner owner, Component parent, Lines lines) {
        Outcome outcome = new Outcome();
        JCheckBox dontAskAgain = new JCheckBox("Don't ask me again for this server.");
        dontAskAgain.setVisible(lines.offerDontAskAgain());
        JDialog dialog = dialog(owner, parent, lines);
        dialog.setContentPane(buildContentPane(lines, dontAskAgain, dialog, outcome));
        installEscapeAction(dialog);
        dialog.pack();
        Dimension packed = dialog.getSize();
        dialog.setSize(new Dimension(DIALOG_WIDTH, packed.height));
        dialog.setLocationRelativeTo(dialog.getOwner());
        dialog.setVisible(true);
        return new Result(outcome.proceed, lines.offerDontAskAgain() && dontAskAgain.isSelected());
    }

    static JDialog dialog(DialogOwner owner, Component parent, Lines lines) {
        JDialog dialog = new JDialog(owner.of(parent), lines.purpose().title(), Dialog.ModalityType.APPLICATION_MODAL);
        dialog.setDefaultCloseOperation(WindowConstants.DISPOSE_ON_CLOSE);
        return dialog;
    }

    private static JPanel buildContentPane(Lines lines, JCheckBox dontAskAgain, JDialog dialog, Outcome outcome) {
        JPanel content = new JPanel(new BorderLayout(12, 12));
        content.setBorder(BorderFactory.createEmptyBorder(16, 16, 16, 16));
        content.add(buildMessagePanel(lines.lead(), lines.count()), BorderLayout.NORTH);
        content.add(buildToolList(lines.items()), BorderLayout.CENTER);
        content.add(buildFooter(dontAskAgain, lines.purpose().proceedLabel(), dialog, outcome), BorderLayout.SOUTH);
        return content;
    }

    private static JComponent buildMessagePanel(String leadText, String countLine) {
        JPanel panel = new JPanel();
        panel.setLayout(new BoxLayout(panel, BoxLayout.Y_AXIS));
        panel.add(wrappedText(leadText, false));
        panel.add(Box.createVerticalStrut(8));
        panel.add(wrappedText(SPEC_CAVEAT, true));
        panel.add(Box.createVerticalStrut(8));
        panel.add(wrappedText(countLine, false));
        return panel;
    }

    private static JTextArea wrappedText(String text, boolean italic) {
        JTextArea area = new JTextArea(text);
        area.setEditable(false);
        area.setOpaque(false);
        area.setLineWrap(true);
        area.setWrapStyleWord(true);
        area.setFocusable(true);
        area.setBorder(BorderFactory.createEmptyBorder());
        Font base = UIManager.getFont("Label.font");
        if (base != null) {
            area.setFont(italic ? base.deriveFont(Font.ITALIC) : base);
        } else if (italic) {
            area.setFont(area.getFont().deriveFont(Font.ITALIC));
        }
        area.setAlignmentX(Component.LEFT_ALIGNMENT);
        return area;
    }

    private static JComponent buildToolList(List<String> items) {
        JList<String> list = new JList<>(items.toArray(String[]::new));
        list.setVisibleRowCount(Math.min(LIST_VISIBLE_ROWS, Math.max(3, items.size())));
        list.setCellRenderer(new DestructiveToolLineRenderer());
        list.setEnabled(false);
        JScrollPane scroller = new JScrollPane(list);
        scroller.setPreferredSize(new Dimension(660, 140));
        return scroller;
    }

    private static JComponent buildFooter(JCheckBox dontAskAgain, String proceedLabel, JDialog dialog,
                                          Outcome outcome) {
        JPanel footer = new JPanel(new BorderLayout());
        footer.add(dontAskAgain, BorderLayout.WEST);
        JPanel buttons = new JPanel(new FlowLayout(FlowLayout.RIGHT, 8, 0));
        JButton cancel = new JButton("Cancel");
        JButton proceed = new JButton(proceedLabel);
        cancel.addActionListener(e -> dialog.dispose());
        proceed.addActionListener(e -> {
            outcome.proceed = true;
            dialog.dispose();
        });
        JRootPane rootPane = dialog.getRootPane();
        rootPane.setDefaultButton(cancel);
        buttons.add(cancel);
        buttons.add(proceed);
        footer.add(buttons, BorderLayout.EAST);
        return footer;
    }

    private static void installEscapeAction(JDialog dialog) {
        JRootPane rootPane = dialog.getRootPane();
        rootPane.getInputMap(JComponent.WHEN_IN_FOCUSED_WINDOW)
                .put(KeyStroke.getKeyStroke(KeyEvent.VK_ESCAPE, 0), "cancel");
        rootPane.getActionMap().put("cancel", new AbstractAction() {
            @Override
            public void actionPerformed(ActionEvent e) {
                dialog.dispose();
            }
        });
    }

    public record Result(boolean proceed, boolean dontAskAgain) {}

    public record Lines(String lead, String count, List<String> items, Purpose purpose) {
        public Lines {
            items = List.copyOf(items);
        }

        public boolean offerDontAskAgain() {
            return purpose.offerDontAskAgain;
        }
    }

    public enum Purpose {
        SCAN(SCAN_TITLE, "Proceed with scan", true),
        SCAN_WITH_MINED_VALUES(SCAN_TITLE, "Proceed with scan", false),
        MINING(COLLECT_TITLE, "Proceed with collecting", false),
        CHECK_ACCESS(REPLAY_TITLE, "Proceed with Check access", true),
        CHECK_ACCESS_WITH_MINED_VALUES(REPLAY_TITLE, "Proceed with Check access", false);

        private final String title;
        private final String proceedLabel;
        private final boolean offerDontAskAgain;

        Purpose(String title, String proceedLabel, boolean offerDontAskAgain) {
            this.title = title;
            this.proceedLabel = proceedLabel;
            this.offerDontAskAgain = offerDontAskAgain;
        }

        public String title() {
            return title;
        }

        public String proceedLabel() {
            return proceedLabel;
        }
    }

    private static final class Outcome {
        boolean proceed;
    }
}
