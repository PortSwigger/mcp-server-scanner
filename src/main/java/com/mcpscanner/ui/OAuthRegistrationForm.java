package com.mcpscanner.ui;

import com.mcpscanner.auth.oauth.OAuthClientHints;
import com.mcpscanner.auth.oauth.ScopeSelection;
import com.mcpscanner.core.oauth.RegistrationMode;

import java.net.URI;
import java.util.List;

record OAuthRegistrationForm(String issuer, List<String> scopes, ScopeSelection scopeSelection, RegistrationMode mode,
                             String clientId, String clientSecret, String clientIssuer, String metadataUrl,
                             int redirectPort) {

    static boolean usesClient(RegistrationMode mode) {
        return mode == RegistrationMode.AUTO || mode == RegistrationMode.PRE_REGISTERED;
    }

    static boolean usesMetadataDocument(RegistrationMode mode) {
        return mode == RegistrationMode.AUTO || mode == RegistrationMode.CIMD;
    }

    boolean clientIdIgnored() {
        return mode == RegistrationMode.AUTO && !clientId.isBlank() && clientIssuer == null;
    }

    OAuthClientHints hints() {
        String boundClientId = boundClientId();
        requireModeInputs(boundClientId);
        return new OAuthClientHints(issuerUri(), scopes, boundClientId, secretFor(boundClientId),
                mode == RegistrationMode.AUTO || mode == RegistrationMode.DCR,
                redirectPort, OAuthClientHints.DEFAULT_TIMEOUT, mode, metadataUri(), scopeSelection);
    }

    private String boundClientId() {
        if (!usesClient(mode) || clientId.isBlank() || clientIdIgnored()) {
            return null;
        }
        return clientId.trim();
    }

    private String secretFor(String boundClientId) {
        return boundClientId == null || clientSecret.isBlank() ? null : clientSecret.trim();
    }

    private void requireModeInputs(String boundClientId) {
        if (mode == RegistrationMode.CIMD && metadataUrl.isBlank()) {
            throw new IllegalArgumentException("Metadata URL is required for CIMD");
        }
        if (mode == RegistrationMode.PRE_REGISTERED && boundClientId == null) {
            throw new IllegalArgumentException("Client ID is required for pre-registration");
        }
        if (boundClientId != null && (issuer.isBlank() || !issuer.trim().equals(clientIssuer))) {
            throw new IllegalArgumentException("Client ID belongs to another or unknown issuer; re-enter it for this issuer");
        }
        if (usesCimd(boundClientId) && redirectPort == 0) {
            throw new IllegalArgumentException(
                    "CIMD requires a fixed redirect port; set Redirect Port to the port listed in the client metadata document");
        }
    }

    private boolean usesCimd(String boundClientId) {
        return mode == RegistrationMode.CIMD
                || mode == RegistrationMode.AUTO && !metadataUrl.isBlank() && boundClientId == null;
    }

    private URI issuerUri() {
        return issuer.isBlank() ? null : URI.create(issuer.trim());
    }

    private URI metadataUri() {
        return usesMetadataDocument(mode) && !metadataUrl.isBlank() ? URI.create(metadataUrl.trim()) : null;
    }
}
