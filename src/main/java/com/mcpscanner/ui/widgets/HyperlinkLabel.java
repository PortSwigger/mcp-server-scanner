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

    private static final Consumer<Throwable> NO_OP_ERROR_SINK = throwable -> {
    };

    private final Consumer<URI> launcher;

    public HyperlinkLabel(String text, URI target) {
        this(text, target, NO_OP_ERROR_SINK);
    }

    public HyperlinkLabel(String text, URI target, Consumer<Throwable> errorSink) {
        this(text, target, HyperlinkLabel::browse, errorSink);
    }

    HyperlinkLabel(String text, URI target, Consumer<URI> browseAction, Consumer<Throwable> errorSink) {
        super(text);
        this.launcher = daemonLauncher(browseAction, errorSink);
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

    private static Consumer<URI> daemonLauncher(Consumer<URI> browseAction, Consumer<Throwable> errorSink) {
        return uri -> {
            Thread thread = new Thread(() -> browseQuietly(uri, browseAction, errorSink), "hyperlink-launch");
            thread.setDaemon(true);
            thread.start();
        };
    }

    private static void browseQuietly(URI uri, Consumer<URI> browseAction, Consumer<Throwable> errorSink) {
        try {
            browseAction.accept(uri);
        } catch (Exception failure) {
            try {
                errorSink.accept(failure);
            } catch (Exception ignored) {
                // sink is best-effort; never let a throwing sink escape the daemon thread
            }
        }
    }

    private static void browse(URI uri) {
        try {
            if (Desktop.isDesktopSupported() && Desktop.getDesktop().isSupported(Desktop.Action.BROWSE)) {
                Desktop.getDesktop().browse(uri);
            }
        } catch (Exception failure) {
            throw new IllegalStateException("Failed to open " + uri, failure);
        }
    }
}
