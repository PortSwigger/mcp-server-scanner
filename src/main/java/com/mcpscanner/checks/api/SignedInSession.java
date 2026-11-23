package com.mcpscanner.checks.api;

import com.mcpscanner.checks.shared.oauth.SessionCookie;

import java.util.List;
import java.util.Objects;

public record SignedInSession(List<SessionCookie> cookies, String source) {

    public SignedInSession {
        cookies = List.copyOf(cookies);
        Objects.requireNonNull(source, "source must not be null");
    }

    @Override
    public String toString() {
        return "SignedInSession[" + cookies.size() + " cookie(s) from " + source + "]";
    }
}
