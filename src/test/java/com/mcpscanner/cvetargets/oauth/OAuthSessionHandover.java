package com.mcpscanner.cvetargets.oauth;

import com.mcpscanner.auth.grant.RefreshGrant;

import java.util.Objects;
import java.util.Optional;

public record OAuthSessionHandover(String accessToken, Optional<RefreshGrant> grant) {

    public OAuthSessionHandover {
        Objects.requireNonNull(accessToken, "accessToken");
        Objects.requireNonNull(grant, "grant");
    }

    @Override
    public String toString() {
        return "OAuthSessionHandover[grant=" + grant + ", accessToken=redacted]";
    }
}
