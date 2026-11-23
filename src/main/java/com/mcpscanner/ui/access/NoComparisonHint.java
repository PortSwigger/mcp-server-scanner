package com.mcpscanner.ui.access;

import com.mcpscanner.ui.widgets.HyperlinkLabel;
import com.mcpscanner.ui.widgets.ThemeColors;

import javax.swing.JLabel;
import javax.swing.JPanel;
import java.awt.FlowLayout;
import java.util.Optional;

final class NoComparisonHint extends JPanel {

    private static final String BEFORE_LINK = "Tick Compare on another user in ";
    private static final String LINK = "Users";
    private static final String AFTER_LINK = " to compare signed-in users too";

    private final JLabel before = muted(BEFORE_LINK);
    private final HyperlinkLabel identities = new HyperlinkLabel(LINK);
    private final JLabel after = muted(AFTER_LINK);
    private Optional<IdentityShortcuts> shortcuts = Optional.empty();

    NoComparisonHint() {
        super(new FlowLayout(FlowLayout.LEADING, 0, 0));
        setOpaque(false);
        identities.onActivate(() -> shortcuts.ifPresent(IdentityShortcuts::openIdentities));
        add(before);
        add(identities);
        add(after);
    }

    static String sentence() {
        return BEFORE_LINK + LINK + AFTER_LINK;
    }

    void setShortcuts(IdentityShortcuts value) {
        shortcuts = Optional.of(value);
    }

    HyperlinkLabel identitiesLink() {
        return identities;
    }

    String text() {
        return before.getText() + identities.getText() + after.getText();
    }

    private static JLabel muted(String text) {
        JLabel label = new JLabel(text);
        label.setForeground(ThemeColors.muted());
        return label;
    }
}
