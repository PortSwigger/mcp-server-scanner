package com.mcpscanner.client;

import burp.api.montoya.http.message.HttpRequestResponse;

import java.util.List;
import java.util.Objects;

public record PrimaryConnection(String endpoint, TransportType transport, ConnectResult catalog,
                                List<HttpRequestResponse> toolsList) {

    public PrimaryConnection {
        Objects.requireNonNull(endpoint, "endpoint");
        Objects.requireNonNull(transport, "transport");
        Objects.requireNonNull(catalog, "catalog");
        toolsList = List.copyOf(toolsList);
    }

    public PrimaryConnection(String endpoint, TransportType transport, ConnectResult catalog) {
        this(endpoint, transport, catalog, List.of());
    }
}
