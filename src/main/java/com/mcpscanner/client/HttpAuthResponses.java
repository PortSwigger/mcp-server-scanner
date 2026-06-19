package com.mcpscanner.client;

public final class HttpAuthResponses {

    private HttpAuthResponses() {}

    public static boolean isAuthChallenge(int statusCode) {
        return statusCode == 401;
    }
}
