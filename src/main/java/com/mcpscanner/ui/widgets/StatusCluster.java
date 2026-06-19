package com.mcpscanner.ui.widgets;

import com.mcpscanner.ui.state.ConnectionState;
import com.mcpscanner.ui.state.ConnectionStatus;

import javax.swing.Icon;
import javax.swing.JLabel;
import javax.swing.JPanel;
import java.awt.Color;
import java.awt.Component;
import java.awt.FlowLayout;

import java.awt.Graphics;
import java.awt.Graphics2D;
import java.awt.RenderingHints;
import java.util.EnumMap;
import java.util.Map;


public class StatusCluster extends JPanel {

    public static final Color DOT_GRAY = new Color(0x8C8C8C);
    public static final Color DOT_AMBER = new Color(0xC7922B);
    public static final Color DOT_GREEN = new Color(0x4CAF50);
    public static final Color DOT_RED = new Color(0xD95757);

    private static final int DOT_SIZE = 8;
    private static final Map<ConnectionState, Color> STATE_COLORS = buildStateColors();

    private final DotIcon dotIcon = new DotIcon(DOT_GRAY);
    private final JLabel label = SwingHtmlGuard.disableHtml(new JLabel());

    public StatusCluster() {
        super(new FlowLayout(FlowLayout.LEFT, 4, 0));
        setOpaque(false);
        label.setIcon(dotIcon);
        add(label);
        update(ConnectionStatus.disconnected());
    }

    public void update(ConnectionStatus status) {
        dotIcon.setColor(STATE_COLORS.get(status.state()));
        label.setText(status.message());
        label.setToolTipText(SwingHtmlGuard.escapeHtml(status.message()));
        label.repaint();
    }

    Color dotColor() {
        return dotIcon.color();
    }

    String statusText() {
        return label.getText();
    }

    String tooltipText() {
        return label.getToolTipText();
    }

    Object labelHtmlDisabled() {
        return label.getClientProperty("html.disable");
    }

    private static Map<ConnectionState, Color> buildStateColors() {
        Map<ConnectionState, Color> colors = new EnumMap<>(ConnectionState.class);
        colors.put(ConnectionState.DISCONNECTED, DOT_GRAY);
        colors.put(ConnectionState.CONNECTING, DOT_AMBER);
        colors.put(ConnectionState.CONNECTED, DOT_GREEN);
        colors.put(ConnectionState.FAILED, DOT_RED);
        return colors;
    }

    private static final class DotIcon implements Icon {

        private Color color;

        private DotIcon(Color color) {
            this.color = color;
        }

        private void setColor(Color color) {
            this.color = color;
        }

        private Color color() {
            return color;
        }

        @Override
        public void paintIcon(Component component, Graphics graphics, int x, int y) {
            Graphics2D g2 = (Graphics2D) graphics.create();
            try {
                g2.setRenderingHint(RenderingHints.KEY_ANTIALIASING, RenderingHints.VALUE_ANTIALIAS_ON);
                g2.setColor(color);
                g2.fillOval(x, y, DOT_SIZE, DOT_SIZE);
            } finally {
                g2.dispose();
            }
        }

        @Override
        public int getIconWidth() {
            return DOT_SIZE;
        }

        @Override
        public int getIconHeight() {
            return DOT_SIZE;
        }
    }
}
