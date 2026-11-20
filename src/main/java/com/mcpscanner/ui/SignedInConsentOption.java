package com.mcpscanner.ui;

import com.mcpscanner.config.SignedInConsentSetting;
import com.mcpscanner.ui.widgets.OptionRow;
import com.mcpscanner.ui.widgets.ToggleOption;

import javax.swing.JPanel;
import javax.swing.border.EmptyBorder;
import java.awt.BorderLayout;

final class SignedInConsentOption extends JPanel {

    static final String LABEL = "Test OAuth consent with my sign-in";
    static final String HINT = "The OAuth consent check acts with your signed-in session: Burp's cookies for the "
            + "authorization server, or your browser right after an OAuth sign-in at Connect. It obtains a token in "
            + "your name and then revokes it, and registers and deletes probe OAuth clients. On a safe server one "
            + "extra consent tab may appear in your browser after Connect: close it, do not approve it.";

    SignedInConsentOption(SignedInConsentSetting setting) {
        super(new BorderLayout());
        setBorder(new EmptyBorder(4, 8, 8, 8));
        add(new OptionRow(new ToggleOption(LABEL, HINT, setting.optedIn(), setting::optIn)), BorderLayout.CENTER);
    }
}
