package com.mcpscanner.auth.oauth.safety;

import com.mcpscanner.auth.oauth.OAuthUrlValidator;
import com.mcpscanner.logging.McpEventLog;

import java.awt.GraphicsEnvironment;
import java.awt.Window;
import java.lang.reflect.InvocationTargetException;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.function.Supplier;

import javax.swing.JDialog;
import javax.swing.JOptionPane;
import javax.swing.SwingUtilities;

/**
 * Renders a confirmation prompt when {@link SuspiciousDestinationGate} encounters a
 * tolerated-with-prompt classification (loopback, RFC1918, link-local, cloud-metadata,
 * cross-origin, etc.). The gate has already classified the destination — the confirmer
 * only decides whether to surface the prompt and what the user said.
 */
@FunctionalInterface
public interface SuspiciousDestinationConfirmer {

    boolean confirm(SuspiciousDestinationGate.Reason reason);

    static SuspiciousDestinationConfirmer alwaysAllow() {
        return reason -> true;
    }

    static SuspiciousDestinationConfirmer alwaysDeny() {
        return reason -> false;
    }

    /**
     * EDT-marshalling Swing confirmer that parents its dialog to the supplied window (e.g. the
     * Burp suite frame) so the prompt lands on the correct screen in multi-monitor setups. The
     * parent is resolved lazily per prompt to avoid capturing the frame before it exists.
     * In headless JVMs (CI, tests) this falls back to always-deny so connect attempts fail
     * loudly rather than hang.
     */
    static SuspiciousDestinationConfirmer swing(McpEventLog eventLog, Supplier<Window> parentSupplier) {
        return new SwingConfirmer(eventLog, parentSupplier);
    }

    /** Default implementation used by production wiring. */
    final class SwingConfirmer implements SuspiciousDestinationConfirmer {

        private static final String DIALOG_TITLE = "MCP Server Scanner — confirm OAuth destination";

        private final McpEventLog eventLog;
        private final Supplier<Window> parentSupplier;

        SwingConfirmer(McpEventLog eventLog, Supplier<Window> parentSupplier) {
            this.eventLog = eventLog != null ? eventLog : McpEventLog.noop();
            this.parentSupplier = parentSupplier != null ? parentSupplier : () -> null;
        }

        @Override
        public boolean confirm(SuspiciousDestinationGate.Reason reason) {
            if (GraphicsEnvironment.isHeadless()) {
                eventLog.warn("Suspicious OAuth destination prompt suppressed (headless JVM): "
                        + reason.userMessage());
                return false;
            }
            AtomicBoolean approved = new AtomicBoolean(false);
            Runnable promptOnEdt = () -> approved.set(showDialog(reason));
            try {
                if (SwingUtilities.isEventDispatchThread()) {
                    promptOnEdt.run();
                } else {
                    SwingUtilities.invokeAndWait(promptOnEdt);
                }
            } catch (InvocationTargetException | InterruptedException e) {
                Thread.currentThread().interrupt();
                String detail = e.getMessage() != null ? e.getMessage() : e.getClass().getSimpleName();
                eventLog.warn("Suspicious OAuth destination prompt failed: " + detail);
                return false;
            }
            return approved.get();
        }

        private boolean showDialog(SuspiciousDestinationGate.Reason reason) {
            // Security prompt: default focus must be "No" so an accidental Enter does not approve a fetch.
            JOptionPane pane = new JOptionPane(
                    buildMessage(reason),
                    JOptionPane.WARNING_MESSAGE,
                    JOptionPane.YES_NO_OPTION);
            Object[] options = {"Yes", "No"};
            pane.setOptions(options);
            pane.setInitialValue(options[1]);
            JDialog dialog = createDialog(resolveParent(), pane);
            try {
                dialog.setVisible(true);
            } finally {
                dialog.dispose();
            }
            return options[0].equals(pane.getValue());
        }

        Window resolveParent() {
            return parentSupplier.get();
        }

        JDialog createDialog(Window parent, JOptionPane pane) {
            return pane.createDialog(parent, DIALOG_TITLE);
        }

        private static String buildMessage(SuspiciousDestinationGate.Reason reason) {
            StringBuilder body = new StringBuilder();
            body.append("The MCP Server Scanner is about to fetch a URL with suspicious characteristics:\n\n");
            body.append("Purpose: ").append(reason.purpose().label()).append('\n');
            body.append("URL: ").append(reason.destination()).append('\n');
            if (reason.resolvedAddress() != null) {
                body.append("Resolves to: ").append(reason.resolvedAddress()).append('\n');
            }
            body.append("Classification: ").append(String.join(", ", reason.classifications())).append('\n');
            if (reason.purpose().sourceUrl() != null) {
                body.append("Referenced by: ").append(reason.purpose().sourceUrl()).append('\n');
            }
            if (reason.classifications().contains(OAuthUrlValidator.CLASSIFICATION_PLAIN_HTTP_NON_LOOPBACK)) {
                body.append('\n').append("Warning: plain HTTP is in use. An attacker on the network path could")
                        .append(" intercept or tamper with the OAuth flow (token theft, token injection).\n");
            }
            body.append('\n').append("Proceed with the fetch?");
            return body.toString();
        }
    }
}
