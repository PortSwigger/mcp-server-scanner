package com.mcpscanner.auth.oauth;

public class DcrUnsupportedException extends OAuthException {

    public DcrUnsupportedException(String message) {
        super(message);
    }

    public DcrUnsupportedException(String message, Throwable cause) {
        super(message, cause);
    }
}
