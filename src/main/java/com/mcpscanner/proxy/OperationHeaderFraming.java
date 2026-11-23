package com.mcpscanner.proxy;

import com.mcpscanner.mcp.FramedOperation;
import com.mcpscanner.mcp.McpHeaders;
import com.mcpscanner.mcp.ScannerSentinels;

import java.util.HashMap;
import java.util.Map;
import java.util.Optional;
import java.util.function.BiPredicate;

final class OperationHeaderFraming {

    private static final BiPredicate<String, String> TYPED_BY_HAND = (name, value) -> true;
    private static final BiPredicate<String, String> UNREADABLE_RECORD = (name, value) -> false;

    Map<String, String> frame(Map<String, String> outgoing, Map<String, String> framed,
                              Map<String, String> incoming) {
        Map<String, String> headers = withFramedHeaders(outgoing, framed);
        BiPredicate<String, String> sentAsIs = sentAsIs(incoming);
        incoming.forEach((name, value) -> {
            if (FramedOperation.records(name) && sentAsIs.test(name, value)) {
                headers.keySet().removeIf(name::equalsIgnoreCase);
                headers.put(name, value);
            }
        });
        return headers;
    }

    private static BiPredicate<String, String> sentAsIs(Map<String, String> incoming) {
        return headerValue(incoming, ScannerSentinels.FRAMED_OPERATION_HEADER)
                .map(OperationHeaderFraming::payloadsOnly)
                .orElse(TYPED_BY_HAND);
    }

    private static BiPredicate<String, String> payloadsOnly(String recorded) {
        return FramedOperation.decode(recorded)
                .<BiPredicate<String, String>>map(scannerFramed -> (name, value) -> !scannerFramed.framed(name, value))
                .orElse(UNREADABLE_RECORD);
    }

    private static Map<String, String> withFramedHeaders(Map<String, String> outgoing, Map<String, String> framed) {
        Map<String, String> headers = new HashMap<>(outgoing);
        if (!framed.isEmpty()) {
            headers.keySet().removeIf(McpHeaders::isOperationHeader);
            headers.putAll(framed);
        }
        return headers;
    }

    private static Optional<String> headerValue(Map<String, String> headers, String name) {
        return headers.entrySet().stream()
                .filter(header -> header.getKey().equalsIgnoreCase(name))
                .map(Map.Entry::getValue)
                .findFirst();
    }
}
