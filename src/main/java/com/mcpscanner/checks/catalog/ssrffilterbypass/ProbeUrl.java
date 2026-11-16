package com.mcpscanner.checks.catalog.ssrffilterbypass;

import burp.api.montoya.collaborator.CollaboratorPayload;

record ProbeUrl(String host, int port, String url) {

    private static final int HTTP_PORT = 80;

    static ProbeUrl loopback(String host, int port) {
        return new ProbeUrl(host, port, "http://" + host + ":" + port + "/");
    }

    static ProbeUrl control(String host, CollaboratorPayload payload) {
        return new ProbeUrl(host, HTTP_PORT, "http://" + host + "/" + payload);
    }
}
