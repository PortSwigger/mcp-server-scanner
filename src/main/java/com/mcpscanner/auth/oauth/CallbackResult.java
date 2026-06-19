package com.mcpscanner.auth.oauth;

public record CallbackResult(String code, String state, String error, String errorDescription) {

    public boolean isError() {
        return error != null;
    }
}
