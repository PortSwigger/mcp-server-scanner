package com.mcpscanner.architecture.prowiring.communityleak;

import burp.api.montoya.MontoyaApi;

final class McpScannerExtension {

    Object initialize(MontoyaApi api) {
        return api.collaborator();
    }

    Object discovery() {
        return IdentityDiscoveryWiring.create();
    }

    Object features() {
        return new ProfessionalFeatures();
    }
}
