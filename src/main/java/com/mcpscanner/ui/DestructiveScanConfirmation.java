package com.mcpscanner.ui;

import com.mcpscanner.mcp.McpToolDefinition;
import com.mcpscanner.mcp.ToolAnnotations;
import com.mcpscanner.ui.widgets.SwingHtmlGuard;

import javax.swing.BorderFactory;
import javax.swing.Box;
import javax.swing.BoxLayout;
import javax.swing.DefaultListCellRenderer;
import javax.swing.JButton;
import javax.swing.JCheckBox;
import javax.swing.JDialog;
import javax.swing.JLabel;
import javax.swing.JList;
import javax.swing.JPanel;
import javax.swing.JRootPane;
import javax.swing.JScrollPane;
import javax.swing.JTextArea;
import javax.swing.ListCellRenderer;
import javax.swing.KeyStroke;
import javax.swing.SwingConstants;
import javax.swing.WindowConstants;
import java.awt.BorderLayout;
import java.awt.Component;
import java.awt.Dialog;
import java.awt.Dimension;
import java.awt.Font;
import java.awt.FlowLayout;
import java.awt.Window;
import java.awt.event.ActionEvent;
import java.awt.event.KeyEvent;
import java.util.List;
import javax.swing.AbstractAction;
import javax.swing.JComponent;
import javax.swing.UIManager;

public final class DestructiveScanConfirmation {

    private static final String TITLE = "Enable destructive scanning?";
    private static final String LEAD_TEXT =
            "Burp's active scanner will invoke these tools with attacker-controlled inputs. "
            + "This can modify, create, or delete data on the target — irreversible.";
    private static final String SPEC_CAVEAT =
            "Tool annotations are advisory; the server may have understated risk.";
    private static final int LIST_VISIBLE_ROWS = 6;
    private static final int DIALOG_WIDTH = 700;

    private DestructiveScanConfirmation() {
    }

    public static List<McpToolDefinition> nonReadOnly(List<McpToolDefinition> selected) {
        return selected.stream()
                .filter(tool -> !tool.annotations().isExplicitlyReadOnly())
                .toList();
    }

    public static boolean requiresConfirmation(List<McpToolDefinition> selected, boolean dontAskAgain) {
        if (dontAskAgain) {
            return false;
        }
        return !nonReadOnly(selected).isEmpty();
    }

    public static String formatToolLine(McpToolDefinition tool) {
        ToolAnnotations.Display display = tool.annotations().classify();
        String suffix = display == ToolAnnotations.Display.NOT_SPECIFIED
                ? "annotations missing"
                : "destructive";
        return "• " + tool.name() + " (" + suffix + ")";
    }

    public static Result prompt(Component parent, List<McpToolDefinition> nonReadOnly) {
        Window owner = parent != null ? findWindow(parent) : null;
        JDialog dialog = new JDialog(owner, TITLE, Dialog.ModalityType.APPLICATION_MODAL);
        dialog.setDefaultCloseOperation(WindowConstants.DISPOSE_ON_CLOSE);
        Outcome outcome = new Outcome();
        JCheckBox dontAskAgain = new JCheckBox("Don't ask me again for this server.");
        dialog.setContentPane(buildContentPane(nonReadOnly, dontAskAgain, dialog, outcome));
        installEscapeAction(dialog);
        dialog.pack();
        Dimension packed = dialog.getSize();
        dialog.setSize(new Dimension(DIALOG_WIDTH, packed.height));
        dialog.setLocationRelativeTo(parent);
        dialog.setVisible(true);
        return new Result(outcome.proceed, dontAskAgain.isSelected());
    }

    private static JPanel buildContentPane(List<McpToolDefinition> nonReadOnly,
                                            JCheckBox dontAskAgain,
                                            JDialog dialog,
                                            Outcome outcome) {
        JPanel content = new JPanel(new BorderLayout(12, 12));
        content.setBorder(BorderFactory.createEmptyBorder(16, 16, 16, 16));
        content.add(buildMessagePanel(), BorderLayout.NORTH);
        content.add(buildToolList(nonReadOnly), BorderLayout.CENTER);
        content.add(buildFooter(dontAskAgain, dialog, outcome), BorderLayout.SOUTH);
        return content;
    }

    private static JComponent buildMessagePanel() {
        JPanel panel = new JPanel();
        panel.setLayout(new BoxLayout(panel, BoxLayout.Y_AXIS));
        panel.add(wrappedText(LEAD_TEXT, false));
        panel.add(Box.createVerticalStrut(8));
        panel.add(wrappedText(SPEC_CAVEAT, true));
        return panel;
    }

    private static JTextArea wrappedText(String text, boolean italic) {
        JTextArea area = new JTextArea(text);
        area.setEditable(false);
        area.setOpaque(false);
        area.setLineWrap(true);
        area.setWrapStyleWord(true);
        area.setFocusable(false);
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

    private static JComponent buildToolList(List<McpToolDefinition> nonReadOnly) {
        JList<McpToolDefinition> list = new JList<>(nonReadOnly.toArray(McpToolDefinition[]::new));
        list.setVisibleRowCount(Math.min(LIST_VISIBLE_ROWS, Math.max(3, nonReadOnly.size())));
        list.setCellRenderer(new ToolLineRenderer());
        list.setEnabled(false);
        JScrollPane scroller = new JScrollPane(list);
        scroller.setPreferredSize(new Dimension(660, 140));
        return scroller;
    }

    private static JComponent buildFooter(JCheckBox dontAskAgain, JDialog dialog, Outcome outcome) {
        JPanel footer = new JPanel(new BorderLayout());
        footer.add(dontAskAgain, BorderLayout.WEST);
        JPanel buttons = new JPanel(new FlowLayout(FlowLayout.RIGHT, 8, 0));
        JButton cancel = new JButton("Cancel");
        JButton proceed = new JButton("Proceed with scan");
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

    private static Window findWindow(Component component) {
        Component current = component;
        while (current != null) {
            if (current instanceof Window window) {
                return window;
            }
            current = current.getParent();
        }
        return null;
    }

    public record Result(boolean proceed, boolean dontAskAgain) {}

    private static final class Outcome {
        boolean proceed;
    }

    static ListCellRenderer<? super McpToolDefinition> toolLineRendererForTest() {
        return new ToolLineRenderer();
    }

    private static final class ToolLineRenderer extends DefaultListCellRenderer {
        @Override
        public Component getListCellRendererComponent(JList<?> list, Object value, int index,
                                                       boolean isSelected, boolean cellHasFocus) {
            JLabel label = (JLabel) super.getListCellRendererComponent(
                    list, value, index, false, false);
            SwingHtmlGuard.disableHtml(label);
            if (value instanceof McpToolDefinition tool) {
                label.setText(formatToolLine(tool));
            }
            label.setHorizontalAlignment(SwingConstants.LEFT);
            label.setBorder(BorderFactory.createEmptyBorder(2, 8, 2, 8));
            return label;
        }
    }
}
