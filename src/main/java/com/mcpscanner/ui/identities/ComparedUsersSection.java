package com.mcpscanner.ui.identities;

import com.mcpscanner.identity.Identity;
import com.mcpscanner.ui.widgets.SectionHeading;
import com.mcpscanner.ui.widgets.WrappingText;

import javax.swing.JButton;
import javax.swing.JPopupMenu;
import javax.swing.JScrollPane;
import javax.swing.JTable;
import java.util.Optional;

final class ComparedUsersSection {

    private final IdentityUiServices services;
    private final IdentityCommands commands;
    private final IdentityTableModel model;
    private final IdentityTable table;
    private final JScrollPane tableScroll;
    private final IdentitiesToolbar toolbar;
    private final IdentityEditor editor;
    private final WrappingText note = new WrappingText("").muted();
    private final SectionHeading heading = new SectionHeading(UsersPanel.COMPARED_HEADING);
    private final Runnable relayout;
    private boolean reloading;

    ComparedUsersSection(IdentityUiServices services, IdentityCommands commands, PrimaryUserChoice primaryChoice,
                         Runnable openOAuthClient, Runnable relayout) {
        this.services = services;
        this.commands = commands;
        this.relayout = relayout;
        this.model = new IdentityTableModel(services, commands);
        this.table = new IdentityTable(model);
        this.tableScroll = table.scrolled();
        this.toolbar = new IdentitiesToolbar(services, commands, this::selectedIdentity, this::showAddMenu);
        this.editor = new IdentityEditor(services, commands, primaryChoice, EditorRole.COMPARED,
                GrantCredentialForms.NONE, openOAuthClient);
    }

    VerticalStack addTo(VerticalStack stack) {
        return stack.add(heading).add(toolbar).add(tableScroll).add(note).add(editor);
    }

    void listenForSelection() {
        table.getSelectionModel().addListSelectionListener(event -> onSelectionChanged());
    }

    void reload() {
        Optional<String> previous = selectedIdentity().map(Identity::id);
        reloading = true;
        model.reload();
        reloading = false;
        previous.flatMap(model::rowOf).ifPresentOrElse(row -> table.setRowSelectionInterval(row, row),
                table::clearSelection);
        table.fitColumns();
        table.fitHeight(tableScroll);
    }

    void select(String identityId) {
        model.rowOf(identityId).ifPresent(row -> table.setRowSelectionInterval(row, row));
    }

    void clearSelection() {
        table.clearSelection();
    }

    void onSelectionChanged() {
        if (reloading) {
            return;
        }
        Optional<Identity> identity = selectedIdentity();
        toolbar.refresh(identity);
        identity.ifPresentOrElse(editor::show, editor::release);
        editor.setVisible(identity.isPresent());
        note.setText(anonymousSelected() ? UsersPanel.ANONYMOUS_NOTE
                : services.registry().otherUsers().isEmpty() ? UsersPanel.NO_COMPARED_USERS : "");
        note.setVisible(identity.isEmpty() && !note.getText().isEmpty());
        relayout.run();
    }

    SectionHeading heading() {
        return heading;
    }

    JTable table() {
        return table;
    }

    JPopupMenu addMenu() {
        return new AddIdentityMenu(selectedIdentity(), commands);
    }

    IdentityEditor editor() {
        return editor;
    }

    String noteText() {
        return note.isVisible() ? note.getText() : "";
    }

    IdentitiesToolbar toolbar() {
        return toolbar;
    }

    private boolean anonymousSelected() {
        int row = table.getSelectedRow();
        return row >= 0 && row < model.getRowCount() && model.rowAt(row).identity().isEmpty();
    }

    private Optional<Identity> selectedIdentity() {
        int row = table.getSelectedRow();
        if (row < 0 || row >= model.getRowCount()) {
            return Optional.empty();
        }
        return model.rowAt(row).identity().flatMap(identity -> services.registry().find(identity.id()))
                .filter(identity -> !services.registry().isPrimary(identity.id()));
    }

    private void showAddMenu() {
        JButton anchor = toolbar.addButton();
        addMenu().show(anchor, 0, anchor.getHeight());
    }
}
