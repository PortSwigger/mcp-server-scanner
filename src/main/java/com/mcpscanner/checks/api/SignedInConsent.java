package com.mcpscanner.checks.api;

import java.net.URI;
import java.util.List;
import java.util.Optional;

public interface SignedInConsent {

    SignedInConsent OPTED_OUT = new SignedInConsent() {
        @Override
        public boolean optedIn() {
            return false;
        }

        @Override
        public Optional<ScannerClient> scannerClient() {
            return Optional.empty();
        }

        @Override
        public Optional<SignedInSession> cookieSession(URI authorizationEndpoint) {
            return Optional.empty();
        }

        @Override
        public List<BrowserConsentObservation> browserObservations(URI authorizationEndpoint) {
            return List.of();
        }
    };

    boolean optedIn();

    Optional<ScannerClient> scannerClient();

    Optional<SignedInSession> cookieSession(URI authorizationEndpoint);

    List<BrowserConsentObservation> browserObservations(URI authorizationEndpoint);
}
