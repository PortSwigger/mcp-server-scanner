package com.mcpscanner.checks.catalog.oauthauthorizationconsent;

import com.mcpscanner.checks.shared.oauth.ClientMetadata;
import com.mcpscanner.checks.shared.oauth.ProbeCallback;
import com.mcpscanner.checks.shared.oauth.ProbeClientRegistrar;

import java.net.URI;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

final class SignedInProbeClients {

    private static final String FRESH_NAME = "Burp MCP consent probe ";
    private static final String PATH = "scancheck-signed-in-consent-";
    private static final int PROBE_PORT = 49151;

    private final ProbeClientRegistrar registrar;
    private final String unrelatedHost;

    SignedInProbeClients(ProbeClientRegistrar registrar, Optional<URI> scannerRedirect) {
        this.registrar = registrar;
        this.unrelatedHost = ProbeCallback.hostUnrelatedTo(scannerRedirect);
    }

    Optional<RegisteredProbe> fresh() {
        return register(freshName(), unrelatedCallback(), Optional.empty());
    }

    Optional<RegisteredProbe> named(String name) {
        return register(name, unrelatedCallback(), Optional.empty());
    }

    Optional<RegisteredProbe> onHostOf(URI scannerRedirect) {
        int port = scannerRedirect.getPort() == PROBE_PORT ? PROBE_PORT + 1 : PROBE_PORT;
        URI callback = URI.create(scannerRedirect.getScheme() + "://" + scannerRedirect.getHost() + ":" + port
                + "/" + path());
        return register(freshName(), callback, Optional.empty());
    }

    Optional<RegisteredProbe> carrying(Optional<String> softwareId) {
        return register(freshName(), unrelatedCallback(), softwareId);
    }

    private Optional<RegisteredProbe> register(String name, URI callback, Optional<String> softwareId) {
        ClientMetadata codeGrant = ClientMetadata.codeGrant(name, List.of(callback.toString()));
        ClientMetadata metadata = softwareId.map(codeGrant::withSoftwareId).orElse(codeGrant);
        return ProbeClient.register(registrar, metadata, callback).map(client -> new RegisteredProbe(client, name));
    }

    private URI unrelatedCallback() {
        return ProbeCallback.loopback(unrelatedHost, path());
    }

    private static String freshName() {
        return FRESH_NAME + UUID.randomUUID().toString().substring(0, 8);
    }

    private static String path() {
        return PATH + UUID.randomUUID();
    }
}
