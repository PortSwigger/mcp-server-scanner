package com.mcpscanner.http;

import java.util.Objects;

final class SplitExchangeNote {

    static final String DETAIL_SENTENCE = "<p>This server uses the legacy HTTP+SSE transport, so each request "
            + "described above that the server answered on its event stream is shown as two items: the POST with "
            + "the server's own reply to it, then the GET that opened the event stream with the event that answered "
            + "the POST.</p>";

    private SplitExchangeNote() {
    }

    static String addedTo(String detail) {
        String current = Objects.requireNonNullElse(detail, "");
        return current.contains(DETAIL_SENTENCE) ? detail : current + DETAIL_SENTENCE;
    }
}
