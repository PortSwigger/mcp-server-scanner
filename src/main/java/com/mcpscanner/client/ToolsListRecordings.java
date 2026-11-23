package com.mcpscanner.client;

import java.util.function.Supplier;
import java.util.stream.Stream;

final class ToolsListRecordings {

    private final ToolsListRecorder http;
    private final SseToolsListRecorder sse = new SseToolsListRecorder();

    ToolsListRecordings(ToolsListRecorder http) {
        this.http = http;
    }

    RecordedCatalog record(McpScannerSession session, Supplier<ConnectResult> discovery) {
        session.observeSseExchangesWith(sse);
        try {
            ConnectResult catalog = discovery.get();
            return new RecordedCatalog(catalog, Stream.concat(http.recorded().stream(), sse.recorded().stream())
                    .toList());
        } finally {
            sse.stop();
            session.observeSseExchangesWith(SseExchangeListener.IGNORING);
        }
    }
}
