package com.mcpscanner.ui.widgets;

import javax.swing.BorderFactory;
import javax.swing.JTextArea;
import javax.swing.SwingUtilities;
import javax.swing.UIManager;
import javax.swing.text.DefaultCaret;
import java.awt.Dimension;

public final class WrappingText extends JTextArea {

    private static final int NARROW_COLUMNS = 1;

    public WrappingText(String text) {
        super(text);
        setEditable(false);
        setLineWrap(true);
        setWrapStyleWord(true);
        setOpaque(false);
        setColumns(NARROW_COLUMNS);
        setBorder(BorderFactory.createEmptyBorder());
        setFont(UIManager.getFont("Label.font"));
    }

    public WrappingText muted() {
        setForeground(ThemeColors.muted());
        return this;
    }

    public WrappingText fixedWidth(int width) {
        setSize(width, Short.MAX_VALUE);
        setPreferredSize(new Dimension(width, super.getPreferredSize().height));
        return this;
    }

    @Override
    public void setBounds(int x, int y, int width, int height) {
        boolean widthChanged = width != getWidth();
        super.setBounds(x, y, width, height);
        if (widthChanged) {
            SwingUtilities.invokeLater(this::revalidate);
        }
    }

    @Override
    public void updateUI() {
        super.updateUI();
        setFont(UIManager.getFont("Label.font"));
        keepCaretFromScrolling();
    }

    private void keepCaretFromScrolling() {
        if (getCaret() instanceof DefaultCaret caret) {
            caret.setUpdatePolicy(DefaultCaret.NEVER_UPDATE);
        }
    }
}
