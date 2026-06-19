package com.mcpscanner.auth;

import java.util.Set;
import java.util.TreeSet;

public final class AuthHeaderNames {

    private static final String COOKIE = "Cookie";

    private AuthHeaderNames() {}

    public static Set<String> authBearingHeaderNames(AuthStrategy authStrategy) {
        Set<String> names = new TreeSet<>(String.CASE_INSENSITIVE_ORDER);
        names.add(AuthHeaders.AUTHORIZATION_HEADER);
        names.add(COOKIE);
        names.addAll(authStrategy.contributedHeaderNames());
        return names;
    }
}
