package com.mcpscanner.signedin;

import java.util.Locale;
import java.util.Optional;

record SetCookie(String name, String value, Optional<String> domain, String path) {

    private static final String ATTRIBUTE_SEPARATOR = ";";
    private static final String DOMAIN_DOT = ".";
    private static final String ROOT = "/";

    static Optional<SetCookie> parse(String headerValue, String requestPath) {
        String[] parts = headerValue.split(ATTRIBUTE_SEPARATOR);
        int equals = parts[0].indexOf('=');
        if (equals <= 0) {
            return Optional.empty();
        }
        return Optional.of(new SetCookie(parts[0].substring(0, equals).trim(), parts[0].substring(equals + 1).trim(),
                attribute(parts, "domain").map(SetCookie::withoutLeadingDot).filter(domain -> !domain.isEmpty()),
                attribute(parts, "path").filter(path -> path.startsWith(ROOT)).orElse(defaultPath(requestPath))));
    }

    String domainFor(String responseHost) {
        return domain.orElse(lowerCase(responseHost));
    }

    private static Optional<String> attribute(String[] parts, String name) {
        Optional<String> value = Optional.empty();
        for (int index = 1; index < parts.length; index++) {
            String[] pair = parts[index].split("=", 2);
            if (pair.length == 2 && pair[0].trim().equalsIgnoreCase(name)) {
                value = Optional.of(pair[1].trim());
            }
        }
        return value;
    }

    private static String withoutLeadingDot(String domain) {
        String lowered = lowerCase(domain);
        return lowered.startsWith(DOMAIN_DOT) ? lowered.substring(DOMAIN_DOT.length()) : lowered;
    }

    private static String defaultPath(String requestPath) {
        if (requestPath == null || !requestPath.startsWith(ROOT)) {
            return ROOT;
        }
        int lastSlash = requestPath.lastIndexOf(ROOT);
        return lastSlash == 0 ? ROOT : requestPath.substring(0, lastSlash);
    }

    private static String lowerCase(String value) {
        return value.toLowerCase(Locale.ROOT);
    }
}
