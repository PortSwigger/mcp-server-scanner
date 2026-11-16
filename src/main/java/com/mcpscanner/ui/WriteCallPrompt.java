package com.mcpscanner.ui;

import java.awt.Component;

@FunctionalInterface
public interface WriteCallPrompt {

    DestructiveScanConfirmation.Result ask(Component parent, DestructiveScanConfirmation.Lines lines);
}
