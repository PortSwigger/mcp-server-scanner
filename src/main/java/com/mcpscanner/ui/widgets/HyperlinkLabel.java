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

    /** Launches the target URI when the label is clicked. */
    interface Launcher {
        void launch(URI target);
    }

    private final Launcher launcher;

    public HyperlinkLabel(String text, URI target) {
        this(text, target, (Consumer<Throwable>) throwable -> {});
    }

    public HyperlinkLabel(String text, URI target, Consumer<Throwable> errorSink) {
        this(text, target, daemonLauncher(HyperlinkLabel::browse, errorSink));
    }

    HyperlinkLabel(String text, URI target, Launcher launcher) {
        super(text);
        this.launcher = launcher;
        setForeground(ThemeColors.hyperlinkColor(ThemeColors.isDark(panelBackground())));
        setFont(underlined(getFont()));
        setCursor(Cursor.getPredefinedCursor(Cursor.HAND_CURSOR));
        setToolTipText(target.toString());
        addMouseListener(new MouseAdapter() {
            @Override
            public void mouseClicked(MouseEvent event) {
                launcher.launch(target);
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

    static Launcher daemonLauncher(Consumer<URI> browseAction, Consumer<Throwable> errorSink) {
        return target -> {
            Thread thread = new Thread(() -> reportingBrowse(browseAction, target, errorSink), "hyperlink-launch");
            thread.setDaemon(true);
            thread.start();
        };
    }

    private static void reportingBrowse(Consumer<URI> browseAction, URI target, Consumer<Throwable> errorSink) {
        try {
            browseAction.accept(target);
        } catch (Exception e) {
            errorSink.accept(e);
        }
    }

    private static void browse(URI target) {
        try {
            if (Desktop.isDesktopSupported() && Desktop.getDesktop().isSupported(Desktop.Action.BROWSE)) {
                Desktop.getDesktop().browse(target);
            }
        } catch (java.io.IOException e) {
            throw new java.io.UncheckedIOException(e);
        }
    }
}
