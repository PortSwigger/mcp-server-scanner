package com.mcpscanner.checks.shared.oauth;

public final class CookiePath {

    private static final String ROOT = "/";

    private CookiePath() {
    }

    public static boolean admits(String cookiePath, String requestPath) {
        String path = requestPath == null || requestPath.isEmpty() ? ROOT : requestPath;
        return path.equals(cookiePath) || path.startsWith(cookiePath)
                && (cookiePath.endsWith(ROOT) || path.charAt(cookiePath.length()) == '/');
    }
}
