package com.mcpscanner.automation;

public record AuditPathCanaryCommand(String url) {

    public AuditPathCanaryCommand {
        WebUrls.requireWeb(url);
    }
}
