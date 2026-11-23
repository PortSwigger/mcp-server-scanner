package com.mcpscanner.checks.shared.stream;

import java.util.List;
import java.util.Optional;

public final class StreamEvidenceNote {

    public static final String OPENED_OUTSIDE_BURP = "The scanner opened these event streams with its own HTTP "
            + "client, outside Burp, because Burp does not pass open event streams to extensions; each evidence "
            + "response holds the status line, the headers and at most the first bytes the server sent within one "
            + "second.";

    private static final String SENT_OUTSIDE_BURP = "The scanner sent %s with its own HTTP client, outside Burp, "
            + "because Burp does not pass streamed replies to extensions; where the server answered with an event "
            + "stream, the evidence response is the event stream exactly as received, up to the JSON-RPC reply the "
            + "scanner read from it.";
    private static final String EVERY_REQUEST = "these requests";

    private StreamEvidenceNote() {
    }

    public static Optional<String> sentOutsideBurp(List<String> requests, int evidenceRequests) {
        if (requests.isEmpty()) {
            return Optional.empty();
        }
        return Optional.of(SENT_OUTSIDE_BURP.formatted(
                requests.size() == evidenceRequests ? EVERY_REQUEST : inProse(requests)));
    }

    private static String inProse(List<String> requests) {
        int last = requests.size() - 1;
        return last == 0 ? requests.get(0)
                : String.join(", ", requests.subList(0, last)) + " and " + requests.get(last);
    }
}
