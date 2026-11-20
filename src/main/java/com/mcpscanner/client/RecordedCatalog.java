package com.mcpscanner.client;

import burp.api.montoya.http.message.HttpRequestResponse;

import java.util.List;
import java.util.Objects;

public record RecordedCatalog(ConnectResult catalog, List<HttpRequestResponse> toolsList) {

    public RecordedCatalog {
        Objects.requireNonNull(catalog, "catalog");
        toolsList = List.copyOf(toolsList);
    }

    public static RecordedCatalog unrecorded(ConnectResult catalog) {
        return new RecordedCatalog(catalog, List.of());
    }
}
