package com.mcpscanner.checks.api;

public enum SignedInProbe {
    FRESH_NAME,
    SAME_NAME,
    SAME_REDIRECT_HOST,
    SAME_CLIENT_ID_PREFIX,
    SCOPE_UPGRADE
}
