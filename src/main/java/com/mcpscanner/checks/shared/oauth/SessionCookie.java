package com.mcpscanner.checks.shared.oauth;

import java.util.Objects;

public record SessionCookie(String name, String value, String path) {

    private static final String ROOT = "/";

    public SessionCookie {
        Objects.requireNonNull(name, "name must not be null");
        Objects.requireNonNull(value, "value must not be null");
        path = path == null || path.isEmpty() ? ROOT : path;
    }

    @Override
    public String toString() {
        return "SessionCookie[" + name + " for " + path + "]";
    }
}
