package com.mcpscanner.auth.oauth.discovery;

import burp.api.montoya.http.HttpService;

public final class OAuthWellKnownPaths {
    public static final String AS_WELL_KNOWN_PATH = "/.well-known/oauth-authorization-server";
    public static final String PRM_WELL_KNOWN_PATH = "/.well-known/oauth-protected-resource";

    private OAuthWellKnownPaths() {}

    public static String buildUrl(HttpService service, String path) {
        String scheme = service.secure() ? "https" : "http";
        int port = service.port();
        boolean defaultPort = (service.secure() && port == 443) || (!service.secure() && port == 80);
        String host = defaultPort ? service.host() : service.host() + ":" + port;
        return scheme + "://" + host + path;
    }
}
