package com.mcpscanner.ui.detail;

import com.fasterxml.jackson.databind.JsonNode;

import javax.swing.BorderFactory;
import javax.swing.Box;
import javax.swing.BoxLayout;
import javax.swing.JButton;
import javax.swing.JCheckBox;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import java.awt.BorderLayout;
import java.util.function.Consumer;

public final class RawJsonView extends JPanel {

    public static final int PADDING = 8;
    private static final int GAP = 8;

    private final PrettyJson prettyJson = new PrettyJson();
    private final JsonTextPane textPane = new JsonTextPane();
    private final JCheckBox wrapLines = new JCheckBox("Wrap lines", true);
    private final JButton copyButton = new JButton("Copy");
    private final Consumer<String> clipboard;
    private final String hint;

    public RawJsonView(String hint) {
        this(hint, SystemClipboard::copy);
    }

    public RawJsonView(String hint, Consumer<String> clipboard) {
        super(new BorderLayout(0, GAP));
        this.clipboard = clipboard;
        this.hint = hint;
        wrapLines.addActionListener(event -> textPane.setWrapping(wrapLines.isSelected()));
        copyButton.addActionListener(event -> this.clipboard.accept(displayedText()));
        add(toolbar(hint), BorderLayout.NORTH);
        add(new JScrollPane(textPane), BorderLayout.CENTER);
    }

    public void show(JsonNode node) {
        textPane.display(node == null ? "" : prettyJson.print(node));
    }

    public String hint() {
        return hint;
    }

    public String displayedText() {
        return textPane.getText();
    }

    JsonTextPane textPane() {
        return textPane;
    }

    JCheckBox wrapLines() {
        return wrapLines;
    }

    JButton copyButton() {
        return copyButton;
    }

    private JPanel toolbar(String hint) {
        JPanel toolbar = new JPanel();
        toolbar.setLayout(new BoxLayout(toolbar, BoxLayout.X_AXIS));
        toolbar.setOpaque(false);
        toolbar.setBorder(BorderFactory.createEmptyBorder(PADDING, PADDING, 0, PADDING));
        toolbar.add(DetailLabels.muted(hint));
        toolbar.add(Box.createHorizontalGlue());
        toolbar.add(wrapLines);
        toolbar.add(Box.createHorizontalStrut(GAP));
        toolbar.add(copyButton);
        return toolbar;
    }
}
