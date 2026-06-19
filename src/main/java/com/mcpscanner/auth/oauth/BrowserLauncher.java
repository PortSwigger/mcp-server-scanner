package com.mcpscanner.auth.oauth;

import com.mcpscanner.auth.oauth.safety.DefaultSuspiciousDestinationGate;
import com.mcpscanner.auth.oauth.safety.FetchPurpose;
import com.mcpscanner.auth.oauth.safety.SuspiciousDestinationConfirmer;
import com.mcpscanner.auth.oauth.safety.SuspiciousDestinationGate;
import com.mcpscanner.logging.McpEventLog;

import java.awt.Desktop;
import java.net.URI;

@FunctionalInterface
public interface BrowserLauncher {

    String PURPOSE = "Browser launch (authorization endpoint)";

    void open(URI uri);

    static BrowserLauncher desktopLauncher() {
        return desktopLauncher(null);
    }

    static BrowserLauncher desktopLauncher(McpEventLog eventLog) {
        return validated(rawDesktopLauncher(eventLog));
    }

    static BrowserLauncher validated(BrowserLauncher delegate) {
        return validated(delegate, defaultGate(null));
    }

    static BrowserLauncher validated(BrowserLauncher delegate, SuspiciousDestinationGate gate) {
        return uri -> {
            SuspiciousDestinationGate.Decision decision = gate.evaluate(
                    uri, FetchPurpose.of(PURPOSE, null));
            if (decision.isDenied()) {
                String detail = decision.reason() != null
                        ? decision.reason().userMessage()
                        : "destination rejected";
                throw new OAuthException("Refusing to launch browser: " + detail);
            }
            delegate.open(uri);
        };
    }

    private static BrowserLauncher rawDesktopLauncher(McpEventLog eventLog) {
        McpEventLog log = eventLog != null ? eventLog : McpEventLog.noop();
        return uri -> {
            if (!Desktop.isDesktopSupported() || !Desktop.getDesktop().isSupported(Desktop.Action.BROWSE)) {
                log.warn("Browser launch unsupported in this JVM - user must open URL manually");
                throw new OAuthException("Desktop browser launch unsupported in this JVM");
            }
            try {
                Desktop.getDesktop().browse(uri);
            } catch (Exception e) {
                log.warn("Browser launch failed: " + e.getMessage());
                throw new OAuthException("Failed to launch browser: " + e.getMessage(), e);
            }
        };
    }

    private static SuspiciousDestinationGate defaultGate(McpEventLog eventLog) {
        return DefaultSuspiciousDestinationGate.withConfirmer(
                SuspiciousDestinationConfirmer.alwaysDeny(), eventLog);
    }
}
