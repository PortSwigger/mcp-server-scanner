package com.mcpscanner.auth.oauth.discovery;

import com.mcpscanner.auth.oauth.OAuthException;

public class DiscoveryFailedException extends OAuthException {

    public DiscoveryFailedException(String message) {
        super(message);
    }
}
