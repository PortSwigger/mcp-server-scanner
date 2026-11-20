package com.mcpscanner.signedin;

import com.mcpscanner.auth.oauth.OAuthSignIn;
import com.mcpscanner.checks.api.BrowserConsentObservation;
import com.mcpscanner.checks.api.RegisteredClientName;
import com.mcpscanner.checks.api.ScannerClient;
import com.mcpscanner.checks.api.SignedInConsent;
import com.mcpscanner.checks.api.SignedInSession;
import com.mcpscanner.checks.shared.oauth.ClientSecret;
import com.mcpscanner.checks.shared.oauth.ClientSecretMethod;
import com.mcpscanner.config.SignedInConsentSetting;

import java.net.URI;
import java.util.List;
import java.util.Optional;

public final class BurpSignedInConsent implements SignedInConsent {

    private static final ClientSecretMethod CONNECT_SECRET_METHOD = ClientSecretMethod.BASIC;

    private final SignedInConsentSetting setting;
    private final ConnectSignIns signIns;
    private final CookieJarSessions cookieJar;
    private final BrowserConsentObservations observations;

    public BurpSignedInConsent(SignedInConsentSetting setting, ConnectSignIns signIns, CookieJarSessions cookieJar,
                               BrowserConsentObservations observations) {
        this.setting = setting;
        this.signIns = signIns;
        this.cookieJar = cookieJar;
        this.observations = observations;
    }

    @Override
    public boolean optedIn() {
        return setting.optedIn();
    }

    @Override
    public Optional<ScannerClient> scannerClient() {
        return optedIn() ? signIns.current().map(BurpSignedInConsent::scannerClient) : Optional.empty();
    }

    @Override
    public Optional<SignedInSession> cookieSession(URI authorizationEndpoint) {
        return optedIn() ? cookieJar.sessionFor(authorizationEndpoint) : Optional.empty();
    }

    @Override
    public List<BrowserConsentObservation> browserObservations(URI authorizationEndpoint) {
        return optedIn() ? observations.at(authorizationEndpoint) : List.of();
    }

    private static ScannerClient scannerClient(OAuthSignIn signIn) {
        ScannerClient client = new ScannerClient(signIn.issuer(), signIn.clientId(),
                new RegisteredClientName(signIn.clientName()), signIn.redirectUri(), signIn.grantedScopes(),
                signIn.softwareId());
        return signIn.clientSecret()
                .map(secret -> client.withSecret(new ClientSecret(secret, CONNECT_SECRET_METHOD)))
                .orElse(client);
    }
}
