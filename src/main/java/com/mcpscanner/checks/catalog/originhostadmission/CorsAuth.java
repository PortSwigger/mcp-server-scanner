package com.mcpscanner.checks.catalog.originhostadmission;

import java.util.Collection;

enum CorsAuth {
    NONE, COOKIE, HEADER;

    private static final String COOKIE_HEADER = "Cookie";

    static CorsAuth of(Collection<String> carriedCredentialHeaders) {
        if (carriedCredentialHeaders.isEmpty()) {
            return NONE;
        }
        return carriedCredentialHeaders.stream().allMatch(COOKIE_HEADER::equalsIgnoreCase) ? COOKIE : HEADER;
    }
}
