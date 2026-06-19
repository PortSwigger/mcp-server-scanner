package com.mcpscanner.ui.widgets;

import javax.swing.UIManager;
import java.awt.Color;

public final class ThemeColors {

    private static final Color HYPERLINK_DARK = new Color(0x4FC3F7);
    private static final Color HYPERLINK_LIGHT = new Color(0x1565C0);

    private ThemeColors() {
    }

    public static boolean isDark(Color background) {
        if (background == null) {
            return false;
        }
        double luminance = (0.2126 * background.getRed()
                + 0.7152 * background.getGreen()
                + 0.0722 * background.getBlue()) / 255.0;
        return luminance < 0.5;
    }

    public static Color hyperlinkColor(boolean dark) {
        Color fromLaf = UIManager.getColor("Hyperlink.linkColor");
        if (fromLaf != null) {
            return fromLaf;
        }
        return dark ? HYPERLINK_DARK : HYPERLINK_LIGHT;
    }
}
