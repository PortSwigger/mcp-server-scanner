package com.mcpscanner.automation;

public record AuthProbeCommand(String url, boolean useBurpNetworking) {

    public AuthProbeCommand {
        WebUrls.requireWeb(url);
    }
}
