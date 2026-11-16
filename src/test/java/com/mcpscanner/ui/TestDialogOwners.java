package com.mcpscanner.ui;

import com.mcpscanner.ui.widgets.DialogOwner;

final class TestDialogOwners {

    private TestDialogOwners() {
    }

    static DialogOwner withoutSuiteFrame() {
        return new DialogOwner(() -> null);
    }
}
