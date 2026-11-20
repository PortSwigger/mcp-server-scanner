package com.mcpscanner.checks.shared.session;

import burp.api.montoya.http.message.requests.HttpRequest;
import com.mcpscanner.mcp.StreamingResponseReader;

import java.io.IOException;
import java.io.InputStream;
import java.time.Duration;
import java.util.Optional;

final class ProbeReplyReader {

    private static final String DEFAULT_CONTENT_TYPE = "application/json";

    private final StreamingResponseReader reader;

    ProbeReplyReader(Duration responseTimeout) {
        this.reader = new StreamingResponseReader(responseTimeout);
    }

    void awaitReply(Optional<String> contentType, InputStream body, HttpRequest request) throws IOException {
        reader.awaitReply(contentType.orElse(DEFAULT_CONTENT_TYPE), body, request.bodyToString());
    }
}
