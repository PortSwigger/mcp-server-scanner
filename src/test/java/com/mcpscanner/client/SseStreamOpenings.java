package com.mcpscanner.client;

import java.io.InputStream;
import java.net.URI;
import java.net.http.HttpHeaders;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.util.List;
import java.util.Map;

import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

final class SseStreamOpenings {

    private SseStreamOpenings() {
    }

    @SuppressWarnings("unchecked")
    static SseStreamOpening of(String url, Map<String, String> requestHeaders,
                               Map<String, List<String>> responseHeaders) {
        HttpRequest.Builder get = HttpRequest.newBuilder(URI.create(url)).GET();
        requestHeaders.forEach(get::header);
        HttpResponse<InputStream> stream = mock(HttpResponse.class);
        when(stream.request()).thenReturn(get.build());
        when(stream.statusCode()).thenReturn(200);
        when(stream.headers()).thenReturn(HttpHeaders.of(responseHeaders, (name, value) -> true));
        return new SseStreamOpening(stream);
    }
}
