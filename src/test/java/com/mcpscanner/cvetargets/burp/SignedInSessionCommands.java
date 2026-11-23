package com.mcpscanner.cvetargets.burp;

import com.mcpscanner.automation.CommandCookie;
import com.mcpscanner.automation.CommandScannerClient;
import com.mcpscanner.automation.SignedInSessionCommand;
import com.mcpscanner.cvetargets.identities.ProvisionedScannerClient;
import com.mcpscanner.cvetargets.identities.ProvisionedSignedInSession;

import java.net.URI;
import java.util.Optional;
import java.util.Set;

final class SignedInSessionCommands {

    private static final String ROOT = "/";

    private SignedInSessionCommands() {
    }

    static SignedInSessionCommand of(Optional<ProvisionedSignedInSession> provisioned, URI endpoint) {
        return provisioned.map(session -> forHost(session, endpoint.getHost())).orElse(SignedInSessionCommand.NONE);
    }

    private static SignedInSessionCommand forHost(ProvisionedSignedInSession session, String host) {
        return new SignedInSessionCommand(session.cookies().entrySet().stream()
                .map(cookie -> new CommandCookie(host, ROOT, cookie.getKey(), cookie.getValue()))
                .toList(), true, session.client().map(SignedInSessionCommands::scannerClient).orElse(null));
    }

    private static CommandScannerClient scannerClient(ProvisionedScannerClient client) {
        return new CommandScannerClient(URI.create(client.issuer()), URI.create(client.authorizationEndpoint()),
                Optional.ofNullable(client.registrationEndpoint()).map(URI::create).orElse(null), client.clientId(),
                client.clientName(), URI.create(client.redirectUri()), Set.copyOf(client.grantedScopes()),
                client.softwareId());
    }
}
