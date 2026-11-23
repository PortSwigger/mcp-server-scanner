package com.mcpscanner.testutil;

import burp.api.montoya.http.message.HttpHeader;

import java.util.List;

import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.mock;

public final class SpentRateLimitQuota {

    public static final String HEADER_LINES = "RateLimit-Remaining: 0\r\nRateLimit-Reset: 44\r\n";

    private SpentRateLimitQuota() {
    }

    public static String addedTo(String rawResponse) {
        return rawResponse.replaceFirst("\r\n", "\r\n" + HEADER_LINES);
    }

    public static List<HttpHeader> mockedHeaders() {
        return List.of(mockedHeader("RateLimit-Remaining", "0"), mockedHeader("RateLimit-Reset", "44"));
    }

    private static HttpHeader mockedHeader(String name, String value) {
        HttpHeader header = mock(HttpHeader.class);
        lenient().when(header.name()).thenReturn(name);
        lenient().when(header.value()).thenReturn(value);
        return header;
    }
}
