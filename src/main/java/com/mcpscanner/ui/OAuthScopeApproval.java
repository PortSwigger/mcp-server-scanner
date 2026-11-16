package com.mcpscanner.ui;

import com.mcpscanner.auth.oauth.OAuthException;
import com.mcpscanner.core.oauth.AuthorizationApproval;
import com.mcpscanner.ui.widgets.DialogOwner;

import javax.swing.JOptionPane;
import javax.swing.SwingUtilities;
import java.awt.Component;
import java.lang.reflect.InvocationTargetException;
import java.net.URI;
import java.util.Set;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.function.Consumer;
import java.util.function.Function;
import java.util.stream.Collectors;

final class OAuthScopeApproval {
    private final URI issuer;
    private final URI resource;
    private final String clientId;
    private final Function<String, Boolean> dialog;
    private final Consumer<String> declineLog;

    OAuthScopeApproval(DialogOwner owner, Component parent, URI issuer, URI resource, String clientId,
                       Consumer<String> declineLog) {
        this(issuer, resource, clientId, message -> JOptionPane.showConfirmDialog(owner.of(parent), message,
                "Approve OAuth scope increase", JOptionPane.YES_NO_OPTION, JOptionPane.QUESTION_MESSAGE)
                == JOptionPane.YES_OPTION, declineLog);
    }

    OAuthScopeApproval(URI issuer, URI resource, String clientId, Function<String, Boolean> dialog) {
        this(issuer, resource, clientId, dialog, message -> { });
    }

    OAuthScopeApproval(URI issuer, URI resource, String clientId, Function<String, Boolean> dialog,
                       Consumer<String> declineLog) {
        this.issuer = issuer;
        this.resource = resource;
        this.clientId = clientId;
        this.dialog = dialog;
        this.declineLog = declineLog;
    }

    AuthorizationApproval approve(Set<String> scopes) {
        if (SwingUtilities.isEventDispatchThread()) {
            throw new OAuthException("OAuth scope authorization requires a background task; reconnect to continue");
        }
        AtomicBoolean approved = new AtomicBoolean();
        try {
            SwingUtilities.invokeAndWait(() -> approved.set(Boolean.TRUE.equals(dialog.apply(message(scopes)))));
        } catch (InterruptedException failure) {
            Thread.currentThread().interrupt();
            throw new OAuthException("OAuth scope approval interrupted; reconnect to continue", failure);
        } catch (InvocationTargetException failure) {
            throw new OAuthException("Cannot display OAuth scope approval; reconnect to continue", failure);
        }
        if (approved.get()) {
            return AuthorizationApproval.APPROVED;
        }
        declineLog.accept("OAuth scope increase declined (" + scopes.stream().sorted().collect(Collectors.joining(", "))
                + "); requests that need these scopes will be rejected");
        return AuthorizationApproval.DENIED;
    }

    private String message(Set<String> scopes) {
        return "The server requires authorization for these OAuth scopes:\n\n"
                + scopes.stream().sorted().collect(Collectors.joining("\n"))
                + "\n\nIssuer: " + issuer + "\nResource: " + resource + "\nClient: " + clientId
                + "\n\nApprove opening the browser to authorize this scope increase?";
    }
}
