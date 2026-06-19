package com.mcpscanner.testutil;

import com.mcpscanner.auth.oauth.BrowserLauncher;
import com.mcpscanner.auth.oauth.CallbackListenerFactory;
import com.mcpscanner.auth.oauth.OAuthAuthorizationFlow;
import com.mcpscanner.auth.oauth.OAuthMetadataConsistencyListener;
import com.mcpscanner.auth.oauth.safety.SuspiciousDestinationGate;
import com.mcpscanner.logging.McpEventLog;

import java.time.Clock;

/**
 * Test-only factory for {@link OAuthAuthorizationFlow} instances routed through a
 * {@link RecordingRealHttp} Burp double. Used by UI tests that need a constructable flow but
 * never drive a real OAuth dance, replacing the deleted no-{@code Http} convenience constructors.
 */
public final class TestOAuthFlows {

    private TestOAuthFlows() {
    }

    /** A flow wired to a fresh {@link RecordingRealHttp}. Requires {@link MontoyaTestFactory#install()}. */
    public static OAuthAuthorizationFlow recording() {
        return new OAuthAuthorizationFlow(
                CallbackListenerFactory.defaultFactory(),
                BrowserLauncher.desktopLauncher(McpEventLog.noop()),
                Clock.systemUTC(),
                // Intentionally permissive: these UI-construction callers never drive a real OAuth dance / reach the network, so gating is irrelevant.
                (url, purpose) -> SuspiciousDestinationGate.Decision.allow(),
                McpEventLog.noop(),
                OAuthMetadataConsistencyListener.noop(),
                new RecordingRealHttp());
    }
}
