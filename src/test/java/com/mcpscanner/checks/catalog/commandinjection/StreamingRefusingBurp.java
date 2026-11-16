package com.mcpscanner.checks.catalog.commandinjection;

import burp.api.montoya.http.Http;
import burp.api.montoya.http.message.requests.HttpRequest;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

final class StreamingRefusingBurp {

    private StreamingRefusingBurp() {}

    static Http http() {
        Http http = mock(Http.class);
        when(http.sendRequest(any(HttpRequest.class)))
                .thenThrow(new RuntimeException(new burp.StreamingRefusalStandIn()));
        return http;
    }
}
