package com.mcpscanner.http.evidence;

import burp.api.montoya.core.Annotations;
import burp.api.montoya.http.message.HttpRequestResponse;

final class TruncationNote {

    static final String DETAIL_SENTENCE = "<p>The response body of at least one exchange below was truncated by "
            + "the scanner's size cap; its notes give the number of bytes kept.</p>";

    private static final String PREFIX = "Response body truncated at ";

    private TruncationNote() {
    }

    static Annotations kept(int bytes) {
        return Annotations.annotations(PREFIX + bytes + " bytes by the scanner's size cap");
    }

    static boolean on(HttpRequestResponse exchange) {
        String notes = exchange == null || exchange.annotations() == null ? null : exchange.annotations().notes();
        return notes != null && notes.startsWith(PREFIX);
    }
}
