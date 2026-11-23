package com.mcpscanner.architecture.prowiring.professionalonly;

import burp.api.montoya.MontoyaApi;

final class ConnectionWiring {

    Object http(MontoyaApi api) {
        return api.http();
    }
}
