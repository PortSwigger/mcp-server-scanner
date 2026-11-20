package com.mcpscanner.ui;

import com.mcpscanner.ui.widgets.SideDrawer;

import javax.swing.JComponent;

interface ScanFeature {

    JComponent bar();

    ScanBarView view();

    void addChecksSection(SideDrawer drawer);

    void addRequestsSection(SideDrawer drawer);

    void openDefaultSection(SideDrawer drawer);

    void bindInventory();

    void cancelRunningScans();

    void shutdown();
}
