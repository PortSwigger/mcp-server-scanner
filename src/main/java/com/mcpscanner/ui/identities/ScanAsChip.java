package com.mcpscanner.ui.identities;

import com.mcpscanner.identity.AnonymousComparison;
import com.mcpscanner.identity.Identity;
import com.mcpscanner.identity.IdentityRegistry;

import javax.swing.BorderFactory;
import javax.swing.JButton;
import javax.swing.JCheckBoxMenuItem;
import javax.swing.JLabel;
import javax.swing.JMenuItem;
import javax.swing.JPopupMenu;
import javax.swing.JRadioButtonMenuItem;
import javax.swing.SwingUtilities;
import java.awt.Component;
import java.awt.Dimension;
import java.awt.Font;
import java.util.stream.Collectors;

public final class ScanAsChip extends JButton {

    static final String NEEDS_CREDENTIALS = "(needs credentials)";
    static final String COMPARING = "Connect, discovery and Scan run as the primary user; Check access replays "
            + "each item as every compared user, with No credential and with a Fake token.";
    static final String NO_COMPARISON = "Check access replays each item with No credential and a Fake token; "
            + "tick Compare on another user to compare signed-in users too.";

    private final IdentityRegistry registry;
    private final CredentialReadiness readiness;
    private final PrimaryUserChoice connectAs;
    private final IdentityCommands commands;
    private final Runnable registryChanged = () -> SwingUtilities.invokeLater(this::refresh);

    ScanAsChip(IdentityUiServices services, IdentityCommands commands) {
        this.registry = services.registry();
        this.commands = commands;
        this.readiness = new CredentialReadiness(services);
        this.connectAs = new PrimaryUserChoice(services, () -> this);
        putClientProperty("JButton.buttonType", "borderless");
        addActionListener(event -> showMenu());
        registry.addListener(registryChanged);
        refresh();
    }

    public void dispose() {
        registry.removeListener(registryChanged);
    }

    public void refresh() {
        boolean comparing = !registry.compared().isEmpty();
        setText("Scan as " + registry.primaryUser().name() + " · " + comparison() + " ▾");
        setToolTipText(comparing ? COMPARING : NO_COMPARISON);
    }

    JPopupMenu menu() {
        JPopupMenu menu = new JPopupMenu();
        menu.add(heading("Scan as"));
        registry.identities().forEach(identity -> menu.add(scanAsItem(identity)));
        menu.addSeparator();
        menu.add(heading("Compare"));
        registry.otherUsers().forEach(identity -> menu.add(compareItem(identity)));
        return menu;
    }

    private void showMenu() {
        JPopupMenu menu = menu();
        menu.show(this, 0, -menu.getPreferredSize().height);
    }

    private String comparison() {
        String names = registry.compared().stream().map(Identity::name).collect(Collectors.joining(", "));
        return names.isEmpty() ? "no comparison" : "compare " + AnonymousComparison.alongside(names);
    }

    private JMenuItem scanAsItem(Identity identity) {
        boolean current = connectAs.isCurrent(identity);
        boolean choosable = connectAs.canChoose(identity);
        JRadioButtonMenuItem item = new JRadioButtonMenuItem(labelled(identity, current || choosable), current);
        item.setEnabled(current || choosable);
        item.addActionListener(event -> connectAs.choose(identity.id()));
        return item;
    }

    private JMenuItem compareItem(Identity identity) {
        boolean ready = readiness.hasCredentials(identity);
        JCheckBoxMenuItem item = new JCheckBoxMenuItem(labelled(identity, ready), identity.compared());
        item.setEnabled(ready);
        item.addActionListener(event -> commands.setCompared(identity, item.isSelected()));
        return item;
    }

    private static String labelled(Identity identity, boolean ready) {
        return ready ? identity.name() : identity.name() + " " + NEEDS_CREDENTIALS;
    }

    private static JLabel heading(String text) {
        JLabel heading = new JLabel(text);
        heading.setFont(heading.getFont().deriveFont(Font.BOLD));
        heading.setBorder(BorderFactory.createEmptyBorder(4, 8, 2, 8));
        heading.setAlignmentX(Component.CENTER_ALIGNMENT);
        heading.setMaximumSize(new Dimension(Integer.MAX_VALUE, heading.getPreferredSize().height));
        return heading;
    }
}
