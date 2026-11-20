package com.mcpscanner.ui.identities;

import com.mcpscanner.identity.credentials.CredentialNeed;
import com.mcpscanner.ui.widgets.HyperlinkLabel;
import com.mcpscanner.ui.widgets.PrimaryActionButton;
import com.mcpscanner.ui.widgets.SecretField;
import com.mcpscanner.ui.widgets.SwingHtmlGuard;
import com.mcpscanner.ui.widgets.ThemeColors;
import com.mcpscanner.ui.widgets.WarningBanner;

import javax.swing.BorderFactory;
import javax.swing.Box;
import javax.swing.BoxLayout;
import javax.swing.JButton;
import javax.swing.JComponent;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.UIManager;
import java.awt.Component;
import java.awt.Dimension;
import java.awt.Font;
import java.util.Arrays;
import java.util.Optional;

public final class CredentialPrompt extends JPanel {

    public interface Actions {
        void connect();

        void openOAuthClient();

        void openPrimaryUser();
    }

    static final int TOKEN_WIDTH = 240;
    private static final int GAP = 8;

    private final IdentityUiServices services;
    private final PrimaryCredentialSave save;
    private final Actions actions;
    private final UsersMode mode;
    private final JLabel title = SwingHtmlGuard.disableHtml(new JLabel());
    private final SecretField token = new SecretField("token");
    private final PrimaryActionButton saveAndConnect = new PrimaryActionButton("Save and connect");
    private final HyperlinkLabel otherCredentials = new HyperlinkLabel("Other credentials…");
    private final PrimaryActionButton action = new PrimaryActionButton("");
    private final JButton dismiss = new JButton("Cancel");
    private Optional<CredentialNeed> shown = Optional.empty();
    private Optional<CredentialNeed> dismissed = Optional.empty();

    CredentialPrompt(IdentityUiServices services, Actions actions) {
        this(services, actions, UsersMode.PRIMARY_AND_COMPARED);
    }

    CredentialPrompt(IdentityUiServices services, Actions actions, UsersMode mode) {
        this.services = services;
        this.save = new PrimaryCredentialSave(services);
        this.actions = actions;
        this.mode = mode;
        setLayout(new BoxLayout(this, BoxLayout.LINE_AXIS));
        setBackground(WarningBanner.tint());
        setBorder(BorderFactory.createCompoundBorder(
                BorderFactory.createMatteBorder(1, 3, 1, 1, ThemeColors.warning()),
                BorderFactory.createEmptyBorder(6, 10, 6, 10)));
        title.setFont(title.getFont().deriveFont(Font.BOLD));
        token.setPlaceholder("Paste a bearer token");
        fixWidth(token, TOKEN_WIDTH);
        saveAndConnect.setPrimary(true);
        action.setPrimary(true);
        otherCredentials.setToolTipText("Opens the primary user in Users to choose custom headers or OAuth sign-in");
        assemble(icon(), title, Box.createHorizontalGlue(), token, saveAndConnect, otherCredentials, action, dismiss);
        wire();
        setVisible(false);
    }

    public void show(Optional<CredentialNeed> need) {
        if (need.isEmpty() || dismissed.filter(previous -> sameSubject(previous, need.get())).isPresent()) {
            dismissed = need.isEmpty() ? Optional.empty() : dismissed;
            hidePrompt();
            return;
        }
        if (shown.filter(current -> sameSubject(current, need.get())).isPresent()) {
            retitle(need.get());
        } else {
            render(need.get());
        }
    }

    String titleText() {
        return title.getText();
    }

    SecretField tokenField() {
        return token;
    }

    JButton saveButton() {
        return saveAndConnect;
    }

    HyperlinkLabel otherCredentialsLink() {
        return otherCredentials;
    }

    JButton actionButton() {
        return action;
    }

    JButton dismissButton() {
        return dismiss;
    }

    long rowsInUse() {
        setSize(Math.max(getPreferredSize().width, 1400), getPreferredSize().height);
        doLayout();
        return Arrays.stream(getComponents()).filter(Component::isVisible)
                .filter(component -> component.getWidth() > 0)
                .map(component -> component.getY() + component.getHeight() / 2 > getHeight() / 2 + GAP)
                .distinct().count();
    }

    private void retitle(CredentialNeed need) {
        shown = Optional.of(need);
        CredentialPromptText text = CredentialPromptText.of(need, primaryName(), mode);
        title.setText(text.title());
        title.setForeground(UIManager.getColor("Label.foreground"));
        setToolTipText(SwingHtmlGuard.escapeHtml(text.detail()));
        title.setToolTipText(getToolTipText());
    }

    private void render(CredentialNeed need) {
        retitle(need);
        boolean inline = CredentialPromptText.takesTokenInline(need);
        token.setValue("");
        token.mask();
        token.setVisible(inline);
        saveAndConnect.setVisible(inline);
        otherCredentials.setVisible(inline);
        action.setText(CredentialPromptText.action(need, primaryName()));
        action.setVisible(!inline);
        dismiss.setText(need instanceof CredentialNeed.ToolCallsRefused ? "Dismiss" : "Cancel");
        setVisible(true);
        revalidate();
        repaint();
    }

    private void wire() {
        saveAndConnect.addActionListener(event -> saveAndConnect());
        token.textField().addActionListener(event -> saveAndConnect());
        otherCredentials.onActivate(actions::openPrimaryUser);
        action.addActionListener(event -> shown.ifPresent(this::act));
        dismiss.addActionListener(event -> {
            dismissed = shown;
            hidePrompt();
        });
    }

    private void act(CredentialNeed need) {
        if (need instanceof CredentialNeed.OAuthSignInIncomplete) {
            actions.openOAuthClient();
        } else {
            actions.openPrimaryUser();
        }
    }

    private void saveAndConnect() {
        try {
            save.saveToken(token.value().strip());
        } catch (IllegalArgumentException | IllegalStateException refused) {
            title.setText(refused.getMessage());
            title.setForeground(ThemeColors.error());
            return;
        }
        hidePrompt();
        actions.connect();
    }

    private void hidePrompt() {
        shown = Optional.empty();
        token.setValue("");
        setVisible(false);
    }

    private String primaryName() {
        return services.registry().primaryUser().name();
    }

    private void assemble(Component... parts) {
        for (int index = 0; index < parts.length; index++) {
            if (index > 0) {
                add(Box.createHorizontalStrut(GAP));
            }
            add(parts[index]);
        }
    }

    private static boolean sameSubject(CredentialNeed previous, CredentialNeed next) {
        return previous instanceof CredentialNeed.ToolCallsRefused
                ? next instanceof CredentialNeed.ToolCallsRefused : previous.equals(next);
    }

    private static void fixWidth(JComponent component, int width) {
        Dimension size = new Dimension(width, component.getPreferredSize().height);
        component.setPreferredSize(size);
        component.setMaximumSize(size);
        component.setMinimumSize(size);
    }

    private static JLabel icon() {
        JLabel icon = new JLabel("▲");
        icon.setForeground(ThemeColors.warning());
        return icon;
    }
}
