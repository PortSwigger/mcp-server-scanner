package com.mcpscanner.cvetargets.identities;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.mcpscanner.checks.api.RegisteredClientName;
import com.mcpscanner.checks.api.ScannerClient;

import java.net.URI;
import java.util.List;
import java.util.Optional;
import java.util.Set;

@JsonIgnoreProperties(ignoreUnknown = true)
public record ProvisionedScannerClient(String issuer, String authorizationEndpoint, String registrationEndpoint,
                                       String clientId, String clientName, String redirectUri,
                                       List<String> grantedScopes, String softwareId) {

    public ProvisionedScannerClient {
        grantedScopes = grantedScopes == null ? List.of() : List.copyOf(grantedScopes);
    }

    ScannerClient scannerClient() {
        return new ScannerClient(URI.create(issuer), clientId, RegisteredClientName.of(clientName), URI.create(redirectUri), Set.copyOf(grantedScopes),
                Optional.ofNullable(softwareId));
    }
}
