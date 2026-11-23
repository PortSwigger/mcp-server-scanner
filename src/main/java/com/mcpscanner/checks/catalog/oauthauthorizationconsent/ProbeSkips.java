package com.mcpscanner.checks.catalog.oauthauthorizationconsent;

import com.mcpscanner.checks.api.OAuthSkipLog;
import com.mcpscanner.checks.api.SignedInProbe;
import com.mcpscanner.checks.api.SkipReason;

final class ProbeSkips {

    private final OAuthSkipLog skips;
    private final String mcpEndpoint;

    ProbeSkips(OAuthSkipLog skips, String mcpEndpoint) {
        this.skips = skips;
        this.mcpEndpoint = mcpEndpoint;
    }

    void notRun(SignedInProbe probe, SkipReason reason) {
        skips.notRun("the " + ConsentShortcut.of(probe).label() + " probe of the signed-in consent test for "
                + mcpEndpoint, reason);
    }
}
