package com.mcpscanner.checks.shared.auth;

import com.mcpscanner.auth.AuthHeaderNames;
import com.mcpscanner.auth.AuthStrategy;

import java.util.List;

final class CustomCredentialHeaders {

    private static final String COOKIE = "Cookie";

    private CustomCredentialHeaders() {
    }

    static List<String> of(AuthStrategy strategy) {
        return strategy.contributedHeaderNames().stream()
                .filter(name -> !AuthHeaderNames.AUTHORIZATION.equalsIgnoreCase(name) && !COOKIE.equalsIgnoreCase(name))
                .toList();
    }
}
