package com.mcpscanner.client;

import com.mcpscanner.http.evidence.WireRecord;

import java.io.Closeable;
import java.io.IOException;
import java.io.InputStream;
import java.net.URI;
import java.util.List;
import java.util.Map;
import java.util.Optional;

public record ProtocolHttpResponse(int status, Map<String, List<String>> headers, InputStream body, URI uri,
                                   Optional<WireRecord> wire) implements Closeable {

    public ProtocolHttpResponse(int status, Map<String, List<String>> headers, InputStream body, URI uri) {
        this(status, headers, body, uri, Optional.empty());
    }

    public ProtocolHttpResponse withBody(InputStream replaced) {
        return new ProtocolHttpResponse(status, headers, replaced, uri, wire);
    }

    public Optional<String> firstHeader(String name) {
        return headerValues(name).stream().findFirst();
    }

    public List<String> headerValues(String name) {
        return headers.entrySet().stream()
                .filter(header -> header.getKey().equalsIgnoreCase(name))
                .flatMap(header -> header.getValue().stream())
                .toList();
    }

    @Override
    public void close() throws IOException {
        body.close();
    }
}
