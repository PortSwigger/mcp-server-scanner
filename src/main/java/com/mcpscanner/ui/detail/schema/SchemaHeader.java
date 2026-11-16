package com.mcpscanner.ui.detail.schema;

import com.mcpscanner.ui.detail.Chip;
import com.mcpscanner.ui.detail.RawJsonView;
import com.mcpscanner.ui.widgets.WrapLayout;

import javax.swing.BorderFactory;
import javax.swing.JPanel;
import java.awt.BorderLayout;
import java.awt.FlowLayout;

final class SchemaHeader extends JPanel {

    private static final int GAP = 8;

    SchemaHeader(String heading, String summary, String dialect) {
        super(new BorderLayout(GAP, 0));
        setOpaque(false);
        setBorder(BorderFactory.createEmptyBorder(RawJsonView.PADDING, 0, 0, 0));
        JPanel title = new JPanel(new WrapLayout(FlowLayout.LEFT, GAP, 0));
        title.setOpaque(false);
        title.add(SchemaLabels.strong(heading));
        title.add(SchemaLabels.muted(summary));
        add(title, BorderLayout.CENTER);
        add(Chip.neutral("JSON Schema " + dialect), BorderLayout.EAST);
    }
}
