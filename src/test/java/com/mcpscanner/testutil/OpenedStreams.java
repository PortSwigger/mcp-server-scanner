package com.mcpscanner.testutil;

import java.net.URI;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;

import static org.mockito.Mockito.lenient;

public final class OpenedStreams {

    public static final HttpRequest OPENING_GET = HttpRequest.newBuilder(URI.create("http://upstream/sse")).GET().build();

    private OpenedStreams() {
    }

    public static <T> HttpResponse<T> openedByAGet(HttpResponse<T> stream) {
        lenient().when(stream.request()).thenReturn(OPENING_GET);
        return stream;
    }
}
