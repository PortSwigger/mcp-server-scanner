package com.mcpscanner.ui;

import com.mcpscanner.client.BurpNetworkingSetting;
import com.mcpscanner.ui.widgets.WrappingText;

import javax.swing.BorderFactory;
import javax.swing.BoxLayout;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import java.awt.Dimension;
import java.awt.Window;

final class BurpNetworkingDialog {

    static final String TITLE = "Burp can't read this server's replies";
    static final String TURN_OFF_AND_RECONNECT = "Turn off and reconnect";
    static final String CANCEL = "Cancel";
    static final String EXPLANATION = "This server streams its replies (text/event-stream). Burp doesn't pass "
            + "streamed replies to extensions, so the connection fails while \"" + BurpNetworkingSetting.NAME
            + "\" is on.";
    static final String CONSEQUENCE = "Turning it off sends the extension's requests directly instead. Burp's "
            + "client TLS certificates and upstream proxy won't apply to them until you turn it back on in Settings.";

    private static final int MESSAGE_WIDTH = 440;

    private BurpNetworkingDialog() {
    }

    static boolean offerToTurnOff(Window owner) {
        Object[] choices = {TURN_OFF_AND_RECONNECT, CANCEL};
        int choice = JOptionPane.showOptionDialog(owner, message(), TITLE, JOptionPane.DEFAULT_OPTION,
                JOptionPane.WARNING_MESSAGE, null, choices, TURN_OFF_AND_RECONNECT);
        return choice == 0;
    }

    private static JPanel message() {
        JPanel message = new JPanel();
        message.setLayout(new BoxLayout(message, BoxLayout.Y_AXIS));
        message.add(paragraph(EXPLANATION));
        message.add(paragraph(CONSEQUENCE));
        return message;
    }

    private static WrappingText paragraph(String text) {
        WrappingText paragraph = new WrappingText(text);
        paragraph.setBorder(BorderFactory.createEmptyBorder(0, 0, 8, 0));
        paragraph.setSize(new Dimension(MESSAGE_WIDTH, Short.MAX_VALUE));
        paragraph.setPreferredSize(new Dimension(MESSAGE_WIDTH, paragraph.getPreferredSize().height));
        return paragraph;
    }
}
