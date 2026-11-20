package com.mcpscanner.automation;

public record CommandCookie(String domain, String path, String name, String value) {

    private static final String ROOT = "/";

    public CommandCookie {
        domain = required(domain, "domain");
        name = required(name, "name");
        path = path == null || path.isBlank() ? ROOT : path;
        value = value == null ? "" : value;
    }

    private static String required(String field, String label) {
        if (field == null || field.isBlank()) {
            throw new IllegalArgumentException("cookie " + label + " is required");
        }
        return field;
    }

    @Override
    public String toString() {
        return "CommandCookie[" + name + " for " + domain + path + "]";
    }
}
