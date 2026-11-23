package com.mcpscanner.cvetargets.identities;

import com.mcpscanner.checks.api.BrowserConsentObservation;
import com.mcpscanner.checks.api.ScannerClient;
import com.mcpscanner.checks.api.SignedInConsent;
import com.mcpscanner.checks.api.SignedInSession;
import com.mcpscanner.checks.shared.oauth.SessionCookie;

import java.net.URI;
import java.util.List;
import java.util.Locale;
import java.util.Objects;
import java.util.Optional;

final class ArmSignedInConsent implements SignedInConsent {

    private static final String SOURCE = "the target's signed-in session provision script";
    private static final String ROOT_PATH = "/";

    private volatile URI armOrigin;
    private volatile ProvisionedSignedInSession session;

    void provide(URI armEndpoint, ProvisionedSignedInSession provisioned) {
        armOrigin = origin(armEndpoint);
        session = provisioned;
    }

    @Override
    public boolean optedIn() {
        return true;
    }

    @Override
    public Optional<ScannerClient> scannerClient() {
        return Optional.ofNullable(session).flatMap(ProvisionedSignedInSession::client)
                .map(ProvisionedScannerClient::scannerClient);
    }

    @Override
    public Optional<SignedInSession> cookieSession(URI authorizationEndpoint) {
        ProvisionedSignedInSession provisioned = session;
        if (provisioned == null || !origin(authorizationEndpoint).equals(armOrigin)) {
            return Optional.empty();
        }
        return Optional.of(new SignedInSession(provisioned.cookies().entrySet().stream()
                .map(cookie -> new SessionCookie(cookie.getKey(), cookie.getValue(), ROOT_PATH)).toList(), SOURCE));
    }

    @Override
    public List<BrowserConsentObservation> browserObservations(URI authorizationEndpoint) {
        return List.of();
    }

    private static URI origin(URI uri) {
        String scheme = Objects.requireNonNullElse(uri.getScheme(), "").toLowerCase(Locale.ROOT);
        String host = Objects.requireNonNullElse(uri.getHost(), "").toLowerCase(Locale.ROOT);
        return URI.create(scheme + "://" + host + ":" + port(scheme, uri.getPort()));
    }

    private static int port(String scheme, int port) {
        if (port != -1) {
            return port;
        }
        return "https".equals(scheme) ? 443 : 80;
    }
}
