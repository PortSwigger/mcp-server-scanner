package com.mcpscanner.client;

import java.io.IOException;
import java.time.Duration;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.Supplier;

final class ConnectToolsListRecording implements ProtocolHttpTransport {

    private final ProtocolHttpTransport delegate;
    private final AtomicReference<ProtocolHttpTransport> current;

    ConnectToolsListRecording(ProtocolHttpTransport delegate) {
        this.delegate = delegate;
        this.current = new AtomicReference<>(delegate);
    }

    static ConnectToolsListRecording sseOnly() {
        return new ConnectToolsListRecording((request, timeout) -> {
            throw new IllegalStateException("The session sends through its own transport");
        });
    }

    @Override
    public ProtocolHttpResponse send(ProtocolHttpRequest request, Duration timeout)
            throws IOException, InterruptedException {
        return current.get().send(request, timeout);
    }

    RecordedCatalog record(McpScannerSession session, Supplier<ConnectResult> discovery) {
        ToolsListRecorder http = new ToolsListRecorder(delegate);
        current.set(http);
        try {
            return new ToolsListRecordings(http).record(session, discovery);
        } finally {
            current.set(delegate);
        }
    }
}
