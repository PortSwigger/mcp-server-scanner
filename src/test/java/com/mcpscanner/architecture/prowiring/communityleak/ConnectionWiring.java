package com.mcpscanner.architecture.prowiring.communityleak;

import burp.api.montoya.MontoyaApi;

final class ConnectionWiring {

    Object scanner(MontoyaApi api) {
        return api.scanner();
    }
}
