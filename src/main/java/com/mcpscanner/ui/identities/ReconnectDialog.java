package com.mcpscanner.ui.identities;

import javax.swing.JComponent;
import javax.swing.JDialog;
import javax.swing.KeyStroke;
import java.awt.Dialog;
import java.awt.Window;
import java.awt.event.KeyEvent;
import java.util.concurrent.atomic.AtomicBoolean;

final class ReconnectDialog {

    private ReconnectDialog() {
    }

    static boolean confirm(Window owner, String user, String previousUser) {
        AtomicBoolean accepted = new AtomicBoolean();
        JDialog dialog = new JDialog(owner, "Reconnect", Dialog.ModalityType.APPLICATION_MODAL);
        ReconnectConfirmation content = new ReconnectConfirmation(user, previousUser, choice -> {
            accepted.set(choice);
            dialog.dispose();
        });
        dialog.setContentPane(content);
        dialog.getRootPane().setDefaultButton(content.reconnectButton());
        dialog.getRootPane().registerKeyboardAction(event -> dialog.dispose(),
                KeyStroke.getKeyStroke(KeyEvent.VK_ESCAPE, 0), JComponent.WHEN_IN_FOCUSED_WINDOW);
        dialog.pack();
        dialog.setLocationRelativeTo(owner);
        dialog.setVisible(true);
        return accepted.get();
    }
}
