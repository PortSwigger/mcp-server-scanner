package com.mcpscanner.cvetargets.burp;

import com.mcpscanner.client.TransportType;
import com.mcpscanner.cvetargets.run.IssueSummary;

import java.util.List;

final class LegacySseEvidenceShape {

    private static final String EXCHANGE_SEPARATOR = " => ";
    private static final String EVENT_STREAM = "text/event-stream";

    private LegacySseEvidenceShape() {
    }

    static void require(TransportType transport, List<IssueSummary> issues) {
        if (transport == TransportType.SSE) {
            issues.forEach(LegacySseEvidenceShape::requireTwoItemExchanges);
        }
    }

    private static void requireTwoItemExchanges(IssueSummary issue) {
        List<String> evidence = issue.evidence();
        for (int index = 0; index < evidence.size(); index++) {
            String item = evidence.get(index);
            if (isPost(item) && answeredByStream(item)) {
                throw misshapen(issue, item, "a POST answered by the event stream instead of the server's own reply");
            }
            if (answeredByStream(item) && (index == 0 || !isPost(evidence.get(index - 1)))) {
                throw misshapen(issue, item, "a stream event not immediately preceded by its POST");
            }
        }
    }

    private static boolean isPost(String item) {
        return item.startsWith("POST ");
    }

    private static boolean answeredByStream(String item) {
        int separator = item.indexOf(EXCHANGE_SEPARATOR);
        return separator >= 0 && item.substring(separator).toLowerCase().contains(EVENT_STREAM);
    }

    private static IllegalStateException misshapen(IssueSummary issue, String item, String shape) {
        return new IllegalStateException("Legacy SSE issue '" + issue.name() + "' has " + shape
                + ", so its evidence is not the wire exchange: " + item);
    }
}
