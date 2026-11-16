package com.mcpscanner.ui.identities;

import com.mcpscanner.identity.Identity;
import com.mcpscanner.identity.SharedCredentials;
import com.mcpscanner.identity.IdentityAuthKind;
import com.mcpscanner.identity.IdentityRole;
import com.mcpscanner.ui.widgets.LabeledForm;
import com.mcpscanner.ui.widgets.LabelledRenderer;
import com.mcpscanner.ui.widgets.WrappingText;

import javax.swing.JButton;
import javax.swing.JComboBox;
import javax.swing.JComponent;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JTextField;
import java.awt.BorderLayout;
import java.awt.Font;
import java.awt.Rectangle;
import java.awt.event.FocusAdapter;
import java.awt.event.FocusEvent;
import java.util.List;
import java.util.Optional;

final class IdentityEditor extends JPanel {

    private static final int LABEL_WIDTH = 120;

    private final IdentityUiServices services;
    private final IdentityCommands commands;
    private final EditorRole role;
    private final BoundIdentity bound;
    private final JLabel title = new JLabel();
    private final JTextField name = new JTextField();
    private final FollowedText shownName = new FollowedText(name);
    private final AuthKindChoices kinds;
    private final JComboBox<IdentityAuthKind> auth = new JComboBox<>();
    private final WrappingText kindHelp = new WrappingText("").muted();
    private final PrivateMarkerField marker = new PrivateMarkerField();
    private final CredentialSection credentials;
    private final ComparedUserFields compared;
    private final SharedCredentialsBanner sharedCredentials;
    private final StaleConnectionBanner staleConnection;
    private LabeledForm.Row kindHelpRow;

    IdentityEditor(IdentityUiServices services, IdentityCommands commands, PrimaryUserChoice primaryChoice,
                   EditorRole role, GrantCredentialForms grantForms, Runnable openOAuthClient) {
        super(new BorderLayout());
        this.services = services;
        this.commands = commands;
        this.role = role;
        this.bound = new BoundIdentity(services.registry());
        this.kinds = new AuthKindChoices(auth, grantForms);
        this.credentials = new CredentialSection(services, commands, bound, grantForms, openOAuthClient);
        this.compared = new ComparedUserFields(services, commands, primaryChoice, bound);
        this.sharedCredentials = new SharedCredentialsBanner(new SharedCredentials(services.registry()));
        this.staleConnection = new StaleConnectionBanner(services);
        setOpaque(false);
        title.setFont(title.getFont().deriveFont(Font.BOLD));
        title.setVisible(role == EditorRole.COMPARED);
        auth.setRenderer(LabelledRenderer.of(IdentityAuthKind.class, AuthLabels::identityKind));
        add(title, BorderLayout.NORTH);
        add(form(), BorderLayout.CENTER);
        wireEdits();
    }

    void show(Identity identity) {
        if (bound.rebind(identity)) {
            bound.load(() -> seed(identity));
        }
        refresh();
    }

    void release() {
        bound.unbind();
    }

    void refresh() {
        bound.current().ifPresent(identity -> {
            title.setText("Compared user: " + identity.name());
            bound.load(() -> {
                kinds.offer(role, identity.authKind());
                credentials.showHeld(identity);
                shownName.follow(identity.name());
                marker.follow(identity.privateMarker());
            });
            Optional<String> help = AuthLabels.help(identity.authKind(), services.registry().detected(identity.id()));
            kindHelp.setText(help.orElse(""));
            kindHelpRow.setVisible(help.isPresent());
            credentials.refresh(identity);
            marker.describe(identity.name());
            sharedCredentials.refresh(identity);
            staleConnection.refresh(identity);
            if (role == EditorRole.COMPARED) {
                compared.refresh(identity);
            }
            revalidate();
            repaint();
        });
    }

    JComponent credentialFocusTarget() {
        return credentials.focusTarget(auth);
    }

    void focusCredentials() {
        JComponent target = credentialFocusTarget();
        target.scrollRectToVisible(new Rectangle(target.getSize()));
        target.requestFocusInWindow();
    }

    String title() {
        return title.getText();
    }

    Optional<Identity> editing() {
        return bound.current();
    }

    JTextField nameField() {
        return name;
    }

    JComboBox<IdentityRole> roleCombo() {
        return compared.roleCombo();
    }

    JComboBox<IdentityAuthKind> authCombo() {
        return auth;
    }

    JButton discoverButton() {
        return compared.discoverButton();
    }

    JButton makePrimaryButton() {
        return compared.makePrimaryButton();
    }

    String roleHelp() {
        return compared.roleHelp();
    }

    String kindHelp() {
        return kindHelp.isVisible() ? kindHelp.getText() : "";
    }

    JTextField markerField() {
        return marker.field();
    }

    CredentialSection credentials() {
        return credentials;
    }

    String sessionLine() {
        return compared.sessionLine();
    }

    List<String> authLabels() {
        return kinds.labels();
    }

    private LabeledForm form() {
        LabeledForm form = new LabeledForm(LABEL_WIDTH);
        form.setOpaque(false);
        form.addRow("Name:", name);
        if (role == EditorRole.COMPARED) {
            compared.addAccessTo(form);
        }
        form.addRow("Auth:", auth);
        kindHelpRow = form.addUnlabeledRow(kindHelp);
        form.addFullWidthRow(sharedCredentials);
        form.addFullWidthRow(staleConnection);
        credentials.addTo(form);
        marker.addTo(form);
        if (role == EditorRole.COMPARED) {
            compared.addStatusTo(form);
        }
        return form;
    }

    private void seed(Identity identity) {
        shownName.seed(identity.name());
        marker.seed(identity.privateMarker());
        credentials.seed(identity);
    }

    private void wireEdits() {
        name.addActionListener(event -> commitName());
        name.addFocusListener(new FocusAdapter() {
            @Override
            public void focusLost(FocusEvent event) {
                commitName();
            }
        });
        auth.addActionListener(event -> bound.ifEditing(this::changeAuthKind));
        marker.onChange(typed -> bound.ifEditing(identity ->
                commands.update(identity.withPrivateMarker(typed))));
    }

    private void commitName() {
        bound.ifEditing(identity -> {
            String typed = name.getText().strip();
            if (!typed.equals(identity.name()) && !commands.update(identity.withName(typed))) {
                shownName.seed(identity.name());
            }
        });
    }

    private void changeAuthKind(Identity identity) {
        IdentityAuthKind kind = (IdentityAuthKind) auth.getSelectedItem();
        if (kind == null || kind == identity.authKind() || !commands.update(identity.withAuthKind(kind))) {
            return;
        }
        services.credentials().clear(identity.id());
        bound.current().ifPresent(updated -> bound.load(() -> credentials.seed(updated)));
        refresh();
    }
}
