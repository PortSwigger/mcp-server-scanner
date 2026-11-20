package com.mcpscanner.checks.catalog.oauthauthorizationconsent;

import com.mcpscanner.checks.api.BrowserConsentObservation;
import com.mcpscanner.checks.api.RegisteredClientName;
import com.mcpscanner.checks.api.ScannerClient;
import com.mcpscanner.checks.api.SignedInConsent;
import com.mcpscanner.checks.api.SignedInSession;
import com.mcpscanner.checks.shared.oauth.SessionCookie;

import java.net.URI;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Optional;

final class FakeSignedInConsent implements SignedInConsent {

    static final String SOURCE = "the Burp cookie jar";

    private Optional<ScannerClient> scannerClient = Optional.of(scannerClient(SignedInServer.SCANNER_ID));
    private Optional<SignedInSession> session = Optional.of(new SignedInSession(
            List.of(new SessionCookie("sid", SignedInServer.SESSION_COOKIE, "/")), SOURCE));
    private final List<BrowserConsentObservation> observations = new ArrayList<>();
    private final List<URI> cookieSessionsAskedFor = new ArrayList<>();

    static ScannerClient scannerClient(String clientId) {
        return scannerClient(clientId, URI.create(SignedInServer.ORIGIN));
    }

    static ScannerClient scannerClient(String clientId, URI issuer) {
        return new ScannerClient(issuer, clientId, RegisteredClientName.of(SignedInServer.SCANNER_NAME), SignedInServer.SCANNER_REDIRECT,
                SignedInServer.GRANTED, Optional.of("burp-mcp"));
    }

    FakeSignedInConsent withScannerClient(Optional<ScannerClient> client) {
        scannerClient = client;
        return this;
    }

    FakeSignedInConsent withoutSession() {
        session = Optional.empty();
        return this;
    }

    FakeSignedInConsent observed(BrowserConsentObservation observation) {
        observations.add(observation);
        return this;
    }

    @Override
    public boolean optedIn() {
        return true;
    }

    @Override
    public Optional<ScannerClient> scannerClient() {
        return scannerClient;
    }

    @Override
    public Optional<SignedInSession> cookieSession(URI authorizationEndpoint) {
        cookieSessionsAskedFor.add(authorizationEndpoint);
        return session;
    }

    List<URI> cookieSessionsAskedFor() {
        return List.copyOf(cookieSessionsAskedFor);
    }

    @Override
    public List<BrowserConsentObservation> browserObservations(URI authorizationEndpoint) {
        return List.copyOf(observations);
    }
}
