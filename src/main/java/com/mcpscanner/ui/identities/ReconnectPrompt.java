package com.mcpscanner.ui.identities;

import com.mcpscanner.ui.widgets.DialogOwner;

import java.awt.Component;

@FunctionalInterface
public interface ReconnectPrompt {

    static ReconnectPrompt modal(DialogOwner owner) {
        return (parent, user, previousUser) -> ReconnectDialog.confirm(owner.of(parent), user, previousUser);
    }

    boolean confirm(Component parent, String user, String previousUser);
}
