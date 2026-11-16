package com.mcpscanner.ui.identities;

import com.mcpscanner.identity.Identity;

import javax.swing.JButton;
import java.util.Optional;

final class DiscoverButton extends JButton {

    static final String LABEL = "Discover";

    private final IdentityUiServices services;

    DiscoverButton(IdentityUiServices services, BoundIdentity bound) {
        super(LABEL);
        this.services = services;
        addActionListener(event -> bound.ifEditing(identity -> services.discovery().discover(identity.id())));
    }

    void refresh(Identity identity) {
        Optional<String> blocker = blocker(identity);
        setEnabled(blocker.isEmpty());
        setToolTipText(blocker.orElse("List this user's tools and resources with its own MCP session"));
    }

    private Optional<String> blocker(Identity identity) {
        if (!services.isConnected()) {
            return Optional.of("Connect first");
        }
        if (services.registry().credential(identity.id()).isEmpty()) {
            return Optional.of("Enter this user's credential first");
        }
        return identity.compared() ? Optional.empty() : Optional.of("Tick Compare first");
    }
}
