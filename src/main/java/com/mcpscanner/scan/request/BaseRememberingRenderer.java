package com.mcpscanner.scan.request;

import burp.api.montoya.http.message.requests.HttpRequest;
import com.mcpscanner.mcp.LaunchedBases;

import java.util.Map;
import java.util.Objects;

public final class BaseRememberingRenderer implements ScanMessageRenderer {

    private final ScanMessageRenderer delegate;
    private final LaunchedBases launched;

    public BaseRememberingRenderer(ScanMessageRenderer delegate, LaunchedBases launched) {
        this.delegate = Objects.requireNonNull(delegate, "delegate");
        this.launched = Objects.requireNonNull(launched, "launched");
    }

    @Override
    public HttpRequest renderJsonRpc(String mcpEndpoint, McpMessage message, Map<String, String> sessionHeaders) {
        HttpRequest rendered = delegate.renderJsonRpc(mcpEndpoint, message, sessionHeaders);
        launched.remember(rendered.bodyToString());
        return rendered;
    }

    @Override
    public HttpRequest renderClientRegistration(ClientRegistrationMessage message) {
        return delegate.renderClientRegistration(message);
    }
}
