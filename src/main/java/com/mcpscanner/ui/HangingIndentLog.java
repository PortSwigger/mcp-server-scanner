package com.mcpscanner.ui;

import com.mcpscanner.ui.widgets.UiStyle;

import javax.swing.JTextPane;
import javax.swing.text.BadLocationException;
import javax.swing.text.Element;
import javax.swing.text.SimpleAttributeSet;
import javax.swing.text.StyleConstants;

final class HangingIndentLog extends JTextPane {

    private final int hangingColumns;

    HangingIndentLog(int hangingColumns) {
        this.hangingColumns = hangingColumns;
        setEditorKit(new BreakAnywhereEditorKit());
        setEditable(false);
        UiStyle.monospaced(this);
    }

    void replaceAll(String text) {
        setText(text);
        hang(0, getDocument().getLength());
    }

    void appendLine(String line) {
        int start = getDocument().getLength();
        insert(start, line);
        hang(start, line.length());
    }

    void removeLines(int first, int count) {
        Element lines = getDocument().getDefaultRootElement();
        int start = lines.getElement(first).getStartOffset();
        remove(start, lines.getElement(first + count - 1).getEndOffset() - start);
    }

    @Override
    public boolean getScrollableTracksViewportWidth() {
        return true;
    }

    private void insert(int offset, String text) {
        try {
            getDocument().insertString(offset, text, null);
        } catch (BadLocationException impossible) {
            throw new IllegalStateException(impossible);
        }
    }

    private void remove(int offset, int length) {
        try {
            getDocument().remove(offset, length);
        } catch (BadLocationException impossible) {
            throw new IllegalStateException(impossible);
        }
    }

    private void hang(int start, int length) {
        float indent = getFontMetrics(getFont()).charWidth('0') * (float) hangingColumns;
        SimpleAttributeSet paragraph = new SimpleAttributeSet();
        StyleConstants.setLeftIndent(paragraph, indent);
        StyleConstants.setFirstLineIndent(paragraph, -indent);
        getStyledDocument().setParagraphAttributes(start, length, paragraph, false);
    }
}
