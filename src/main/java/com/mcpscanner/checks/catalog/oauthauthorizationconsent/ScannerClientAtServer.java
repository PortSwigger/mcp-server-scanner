package com.mcpscanner.checks.catalog.oauthauthorizationconsent;

import com.mcpscanner.checks.api.ScannerClient;
import com.mcpscanner.checks.api.SkipReason;

import java.net.URI;
import java.util.Optional;

record ScannerClientAtServer(Optional<ScannerClient> client, Optional<SkipReason> foreignIssuer) {

    static ScannerClientAtServer of(Optional<ScannerClient> reported, URI probedIssuer) {
        Optional<SkipReason> foreign = reported.filter(client -> !client.issuer().equals(probedIssuer))
                .map(client -> SignedInSkips.foreignIssuer(client.issuer(), probedIssuer));
        return new ScannerClientAtServer(foreign.isPresent() ? Optional.empty() : reported, foreign);
    }

    SkipReason whyUnknown() {
        return foreignIssuer.orElse(SignedInSkips.SCANNER_CLIENT_UNKNOWN);
    }
}
