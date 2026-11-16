package com.mcpscanner.ui.identities;

import com.mcpscanner.identity.Identity;
import com.mcpscanner.identity.IdentityRole;
import com.mcpscanner.ui.widgets.LabeledForm;
import com.mcpscanner.ui.widgets.LabelledRenderer;
import com.mcpscanner.ui.widgets.WrappingText;

import javax.swing.JButton;
import javax.swing.JComboBox;
import javax.swing.JPanel;
import java.awt.FlowLayout;

final class ComparedUserFields {

    private final IdentityUiServices services;
    private final IdentityCommands commands;
    private final PrimaryUserChoice primaryChoice;
    private final BoundIdentity bound;
    private final IdentityStatusText status;
    private final JComboBox<IdentityRole> role = new JComboBox<>(IdentityRole.values());
    private final WrappingText roleHelp = new WrappingText("").muted();
    private final WrappingText session = new WrappingText("").muted();
    private final JButton makePrimary = new JButton("Make primary user");
    private final DiscoverButton discover;
    private LabeledForm.Row roleRow;

    ComparedUserFields(IdentityUiServices services, IdentityCommands commands, PrimaryUserChoice primaryChoice,
                       BoundIdentity bound) {
        this.services = services;
        this.commands = commands;
        this.primaryChoice = primaryChoice;
        this.bound = bound;
        this.status = new IdentityStatusText(services);
        this.discover = new DiscoverButton(services, bound);
        role.setRenderer(LabelledRenderer.of(IdentityRole.class, IdentityRole::label));
        role.addActionListener(event -> bound.ifEditing(identity ->
                commands.update(identity.withRole((IdentityRole) role.getSelectedItem()))));
        makePrimary.addActionListener(event -> bound.ifEditing(identity -> primaryChoice.choose(identity.id())));
    }

    void addAccessTo(LabeledForm form) {
        roleRow = form.addRow("Access:", role);
        form.addUnlabeledRow(roleHelp);
    }

    void addStatusTo(LabeledForm form) {
        form.addRow("Status:", session);
        JPanel actions = new JPanel(new FlowLayout(FlowLayout.LEADING, 0, 0));
        actions.setOpaque(false);
        actions.add(discover);
        actions.add(makePrimary);
        form.addUnlabeledRow(actions);
    }

    void refresh(Identity identity) {
        Identity primary = services.registry().primaryUser();
        bound.load(() -> role.setSelectedItem(identity.role()));
        roleRow.setLabel("Access vs " + primary.name() + ":");
        roleHelp.setText(RoleHelp.describe(identity, primary));
        session.setText(status.session(identity));
        discover.refresh(identity);
        makePrimary.setEnabled(primaryChoice.canChoose(identity));
        makePrimary.setToolTipText(primaryChoice.blocker(identity).orElse(null));
    }

    JComboBox<IdentityRole> roleCombo() {
        return role;
    }

    JButton discoverButton() {
        return discover;
    }

    JButton makePrimaryButton() {
        return makePrimary;
    }

    String roleHelp() {
        return roleHelp.getText();
    }

    String sessionLine() {
        return session.getText();
    }
}
