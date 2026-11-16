package com.mcpscanner.ui.widgets;

import javax.swing.SwingUtilities;
import java.awt.Component;
import java.awt.Window;
import java.util.Objects;
import java.util.Optional;
import java.util.function.Supplier;

public final class DialogOwner {

    private final Supplier<? extends Window> suiteFrame;

    public DialogOwner(Supplier<? extends Window> suiteFrame) {
        this.suiteFrame = Objects.requireNonNull(suiteFrame, "suiteFrame");
    }

    public Window of(Component parent) {
        return Optional.ofNullable(parent).map(DialogOwner::windowOf).orElseGet(suiteFrame);
    }

    private static Window windowOf(Component parent) {
        return parent instanceof Window window ? window : SwingUtilities.getWindowAncestor(parent);
    }
}
