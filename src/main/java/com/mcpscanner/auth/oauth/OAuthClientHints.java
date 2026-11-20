package com.mcpscanner.auth.oauth;

import com.mcpscanner.config.ExtensionConfigStore;
import com.mcpscanner.core.oauth.RegistrationMode;

import java.net.URI;
import java.time.Duration;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;

public record OAuthClientHints(URI issuer,
                                List<String> scopes,
                                String clientId,
                                String clientSecret,
                                boolean allowDcr,
                                int redirectPort,
                                Duration timeout,
                                RegistrationMode registrationMode,
                                URI clientMetadataUrl,
                                ScopeSelection scopeSelection) {

    public static final int DEFAULT_REDIRECT_PORT = ExtensionConfigStore.DEFAULT_OAUTH_REDIRECT_PORT;
    public static final Duration DEFAULT_TIMEOUT = Duration.ofSeconds(120);

    public OAuthClientHints(URI issuer, List<String> scopes, String clientId, String clientSecret,
                            boolean allowDcr, int redirectPort, Duration timeout) {
        this(issuer, scopes, clientId, clientSecret, allowDcr, redirectPort, timeout,
                allowDcr ? RegistrationMode.AUTO : RegistrationMode.PRE_REGISTERED, null);
    }

    public OAuthClientHints(URI issuer, List<String> scopes, String clientId, String clientSecret, boolean allowDcr,
                            int redirectPort, Duration timeout, RegistrationMode registrationMode,
                            URI clientMetadataUrl) {
        this(issuer, scopes, clientId, clientSecret, allowDcr, redirectPort, timeout, registrationMode,
                clientMetadataUrl, ScopeSelection.none());
    }

    public OAuthClientHints withIssuer(URI discoveredIssuer, List<String> discoveredScopes) {
        return new OAuthClientHints(discoveredIssuer, requestedWith(discoveredScopes), clientId, clientSecret,
                allowDcr, redirectPort, timeout, registrationMode, clientMetadataUrl, scopeSelection);
    }

    private List<String> requestedWith(List<String> discoveredScopes) {
        Set<String> requested = new LinkedHashSet<>();
        discoveredScopes.stream().filter(scope -> !scopeSelection.declined().contains(scope)).forEach(requested::add);
        requested.addAll(scopeSelection.customTicked());
        return List.copyOf(requested);
    }

    public OAuthClientHints {
        registrationMode = registrationMode != null ? registrationMode : RegistrationMode.AUTO;
        scopes = scopes != null ? List.copyOf(scopes) : List.of();
        scopeSelection = scopeSelection != null ? scopeSelection : ScopeSelection.none();
        if (timeout == null) {
            timeout = DEFAULT_TIMEOUT;
        }
    }
}
