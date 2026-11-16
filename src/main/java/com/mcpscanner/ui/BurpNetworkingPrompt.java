package com.mcpscanner.ui;

import com.mcpscanner.ui.widgets.DialogOwner;

import java.awt.Component;

@FunctionalInterface
public interface BurpNetworkingPrompt {

    static BurpNetworkingPrompt modal(DialogOwner owner) {
        return parent -> BurpNetworkingDialog.offerToTurnOff(owner.of(parent));
    }

    boolean offerToTurnOff(Component parent);
}
