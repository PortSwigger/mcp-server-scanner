package com.mcpscanner.ui.identities;

import com.mcpscanner.checks.api.Principal;
import com.mcpscanner.identity.IdentityRole;
import com.mcpscanner.ui.widgets.SectionHeading;
import com.mcpscanner.ui.widgets.ThemeColors;
import com.mcpscanner.ui.widgets.WrappingText;

import javax.swing.BorderFactory;
import javax.swing.JButton;
import javax.swing.JPanel;
import javax.swing.JPopupMenu;
import javax.swing.JTable;
import javax.swing.SwingUtilities;
import java.awt.BorderLayout;
import java.util.List;
import java.util.Optional;
import java.util.stream.Stream;

public final class UsersPanel extends JPanel {

    static final String INTRO = "Connect, discovery and Scan run as the primary user. Ticked compared users are "
            + "replayed against them to find what they should not reach.";
    static final String PRIMARY_ONLY_INTRO = "Connect and discovery run as the primary user.";
    static final String PRIMARY_HEADING = "Primary user";
    static final String COMPARED_HEADING = "Compared users";
    static final String NO_COMPARED_USERS = "Add a user to find what one user can reach that another should not.";
    static final String ANONYMOUS_NOTE = Principal.ANONYMOUS_NAME + " sends no credentials. Check access always compares "
            + "against it.";

    private final IdentityUiServices services;
    private final IdentityCommands commands;
    private final UsersMode mode;
    private final IdentityEditor primaryEditor;
    private final Optional<ComparedUsersSection> compared;
    private final WrappingText error = new WrappingText("");
    private final SectionHeading primaryHeading = new SectionHeading(PRIMARY_HEADING);
    private final Runnable unsubscribe;

    public UsersPanel(IdentityUiServices services, GrantCredentialForms grantForms, Runnable openOAuthClient) {
        this(services, grantForms, openOAuthClient, UsersMode.PRIMARY_AND_COMPARED);
    }

    public UsersPanel(IdentityUiServices services, GrantCredentialForms grantForms, Runnable openOAuthClient,
                      UsersMode mode) {
        super(new BorderLayout());
        this.services = services;
        this.mode = mode;
        this.commands = new IdentityCommands(services, this::showError, this::select);
        PrimaryUserChoice primaryChoice = new PrimaryUserChoice(services, () -> this);
        this.compared = mode.comparesUsers()
                ? Optional.of(new ComparedUsersSection(services, commands, primaryChoice, openOAuthClient,
                this::revalidate))
                : Optional.empty();
        this.primaryEditor = new IdentityEditor(services, commands, primaryChoice, EditorRole.primaryIn(mode),
                grantForms, openOAuthClient);
        setBorder(BorderFactory.createEmptyBorder(8, 10, 8, 10));
        error.setForeground(ThemeColors.error());
        error.setVisible(false);
        VerticalStack stack = new VerticalStack(8).add(new WrappingText(intro(mode)).muted()).add(error)
                .add(primaryHeading).add(primaryEditor);
        compared.ifPresent(section -> section.addTo(stack));
        add(stack, BorderLayout.NORTH);
        compared.ifPresent(ComparedUsersSection::listenForSelection);
        this.unsubscribe = services.onChange(() -> SwingUtilities.invokeLater(this::refresh));
        refresh();
    }

    private static String intro(UsersMode mode) {
        return mode.comparesUsers() ? INTRO : PRIMARY_ONLY_INTRO;
    }

    public void refresh() {
        compared.ifPresent(ComparedUsersSection::reload);
        primaryEditor.show(services.registry().primaryUser());
        compared.ifPresentOrElse(ComparedUsersSection::onSelectionChanged, this::revalidate);
    }

    public ScanAsChip scanAsChip() {
        return new ScanAsChip(services, commands);
    }

    public ConnectionIdentityLine connectionIdentityLine() {
        return new ConnectionIdentityLine(services);
    }

    public PrimaryUserPicker primaryUserPicker(Runnable openUsers) {
        return new PrimaryUserPicker(services, openUsers);
    }

    public CredentialPrompt credentialPrompt(CredentialPrompt.Actions actions) {
        return new CredentialPrompt(services, actions, mode);
    }

    public void dispose() {
        unsubscribe.run();
    }

    public void focusPrimaryCredentials() {
        compared.ifPresent(ComparedUsersSection::clearSelection);
        primaryEditor.focusCredentials();
    }

    public void addStarter(IdentityRole role) {
        commands.addStarter(role);
    }

    public void select(String identityId) {
        refresh();
        compared.ifPresent(section -> section.select(identityId));
    }

    JTable table() {
        return comparedUsers().table();
    }

    JPopupMenu addMenu() {
        return comparedUsers().addMenu();
    }

    IdentityEditor primaryEditor() {
        return primaryEditor;
    }

    IdentityEditor comparedEditor() {
        return comparedUsers().editor();
    }

    boolean showingComparedEditor() {
        return comparedEditor().isVisible();
    }

    String noteText() {
        return comparedUsers().noteText();
    }

    List<String> headings() {
        return Stream.concat(Stream.of(primaryHeading), compared.map(ComparedUsersSection::heading).stream())
                .map(SectionHeading::title).toList();
    }

    String errorText() {
        return error.isVisible() ? error.getText() : "";
    }

    JButton addButton() {
        return comparedUsers().toolbar().addButton();
    }

    JButton removeButton() {
        return comparedUsers().toolbar().removeButton();
    }

    JButton signInAllButton() {
        return comparedUsers().toolbar().signInAllButton();
    }

    private ComparedUsersSection comparedUsers() {
        return compared.orElseThrow();
    }

    private void showError(String message) {
        error.setText(message == null ? "" : message);
        error.setVisible(message != null);
        revalidate();
    }
}
