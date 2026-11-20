package com.mcpscanner.ui;

import com.mcpscanner.ui.widgets.SideDrawer;
import com.mcpscanner.ui.widgets.ThemeColors;

import javax.swing.BorderFactory;
import javax.swing.JComponent;
import javax.swing.JLabel;
import javax.swing.JPanel;
import java.awt.FlowLayout;
import java.util.function.Consumer;

final class ScanUnavailable implements ScanFeature {

    static final String NOTE = "Scanning, Check access and Collect IDs require Burp Suite Professional.";

    private final JComponent bar;

    ScanUnavailable(Consumer<Throwable> errorLog) {
        this.bar = noteBar(errorLog);
    }

    private static JComponent noteBar(Consumer<Throwable> errorLog) {
        JPanel bar = new JPanel(new FlowLayout(FlowLayout.LEADING));
        bar.setBorder(BorderFactory.createMatteBorder(1, 0, 0, 0, ThemeColors.separator()));
        bar.add(SupportLinks.create(errorLog));
        JLabel note = new JLabel(NOTE);
        note.setForeground(ThemeColors.muted());
        bar.add(note);
        return bar;
    }

    @Override
    public JComponent bar() {
        return bar;
    }

    @Override
    public ScanBarView view() {
        return ScanBarView.NONE;
    }

    @Override
    public void addChecksSection(SideDrawer drawer) {
    }

    @Override
    public void addRequestsSection(SideDrawer drawer) {
    }

    @Override
    public void openDefaultSection(SideDrawer drawer) {
        drawer.expand(McpScannerTab.USERS_SECTION);
    }

    @Override
    public void bindInventory() {
    }

    @Override
    public void cancelRunningScans() {
    }

    @Override
    public void shutdown() {
    }
}
