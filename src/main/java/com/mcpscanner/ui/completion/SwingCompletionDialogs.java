package com.mcpscanner.ui.completion;

import com.mcpscanner.ui.widgets.DialogOwner;
import com.mcpscanner.ui.widgets.SwingHtmlGuard;
import com.mcpscanner.ui.widgets.UiStyle;

import javax.swing.JLabel;
import javax.swing.JOptionPane;
import javax.swing.JScrollPane;
import javax.swing.JTextArea;
import java.awt.Component;
import java.awt.Dimension;
import java.util.Objects;
import java.util.Optional;

final class SwingCompletionDialogs implements CompletionDialogs {

    static final String PROMPT_TITLE = ValueCompletion.MENU_LABEL;
    private static final Dimension RESULT_SIZE = new Dimension(480, 300);

    private final DialogOwner owner;

    SwingCompletionDialogs(DialogOwner owner) {
        this.owner = Objects.requireNonNull(owner, "owner");
    }

    @Override
    public Optional<String> askCurrentValue(Component parent, String argumentName) {
        Object answer = JOptionPane.showInputDialog(owner.of(parent), promptLabel(argumentName), PROMPT_TITLE,
                JOptionPane.QUESTION_MESSAGE, null, null, "");
        return Optional.ofNullable(answer).map(Object::toString);
    }

    @Override
    public void showResult(Component parent, String title, String text) {
        JScrollPane scroller = new JScrollPane(resultArea(text));
        scroller.setPreferredSize(RESULT_SIZE);
        JOptionPane.showMessageDialog(owner.of(parent), scroller, title, JOptionPane.PLAIN_MESSAGE);
    }

    static JLabel promptLabel(String argumentName) {
        return SwingHtmlGuard.disableHtml(new JLabel(
                "Value typed so far for " + PrintableText.of(argumentName) + " (may be empty):"));
    }

    static JTextArea resultArea(String text) {
        JTextArea area = UiStyle.monospaced(new JTextArea(text));
        area.setEditable(false);
        area.setCaretPosition(0);
        return area;
    }
}
