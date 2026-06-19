package com.mcpscanner.ui.widgets;

import javax.swing.JLabel;
import javax.swing.UIManager;
import java.awt.Color;
import java.awt.Cursor;
import java.awt.Desktop;
import java.awt.font.TextAttribute;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.net.URI;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Consumer;

public final class HyperlinkLabel extends JLabel {

    private final Consumer<URI> launcher;

    public HyperlinkLabel(String text, URI target) {
        this(text, target, defaultDaemonLauncher());
    }

    HyperlinkLabel(String text, URI target, Consumer<URI> launcher) {
        super(text);
        this.launcher = launcher;
        setForeground(ThemeColors.hyperlinkColor(ThemeColors.isDark(panelBackground())));
        setFont(underlined(getFont()));
        setCursor(Cursor.getPredefinedCursor(Cursor.HAND_CURSOR));
        setToolTipText(target.toString());
        addMouseListener(new MouseAdapter() {
            @Override
            public void mouseClicked(MouseEvent event) {
                launcher.accept(target);
            }
        });
    }

    private static Color panelBackground() {
        return UIManager.getColor("Panel.background");
    }

    private static java.awt.Font underlined(java.awt.Font base) {
        Map<TextAttribute, Object> attributes = new HashMap<>(base.getAttributes());
        attributes.put(TextAttribute.UNDERLINE, TextAttribute.UNDERLINE_ON);
        return base.deriveFont(attributes);
    }

    private static Consumer<URI> defaultDaemonLauncher() {
        return uri -> {
            Thread thread = new Thread(() -> browseQuietly(uri), "hyperlink-launch");
            thread.setDaemon(true);
            thread.start();
        };
    }

    private static void browseQuietly(URI uri) {
        try {
            if (Desktop.isDesktopSupported() && Desktop.getDesktop().isSupported(Desktop.Action.BROWSE)) {
                Desktop.getDesktop().browse(uri);
            }
        } catch (Exception ignored) {
        }
    }
}
