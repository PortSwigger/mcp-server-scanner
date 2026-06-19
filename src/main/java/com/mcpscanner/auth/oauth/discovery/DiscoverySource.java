package com.mcpscanner.auth.oauth.discovery;

public enum DiscoverySource {
    WWW_AUTHENTICATE_HEADER("/.well-known/oauth-protected-resource (via WWW-Authenticate)"),
    PRM_WELL_KNOWN("/.well-known/oauth-protected-resource"),
    AS_WELL_KNOWN("/.well-known/oauth-authorization-server");

    private final String displayPath;

    DiscoverySource(String displayPath) {
        this.displayPath = displayPath;
    }

    public String displayPath() {
        return displayPath;
    }
}
