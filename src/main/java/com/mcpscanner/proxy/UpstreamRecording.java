package com.mcpscanner.proxy;

import com.mcpscanner.logging.McpEventLog;
import com.mcpscanner.mcp.LaunchedBases;
import com.mcpscanner.mcp.LegacySseRoutes;

import java.util.Optional;

public record UpstreamRecording(UpstreamCaptures captures, UpstreamExchangeStore store,
                                LegacySseRoutes legacySseRoutes, LaunchedBases launchedBases) {

    public static UpstreamRecording create() {
        return create(McpEventLog.noop());
    }

    public static UpstreamRecording create(McpEventLog eventLog) {
        return new UpstreamRecording(new UpstreamCaptures(), new UpstreamExchangeStore(eventLog),
                new LegacySseRoutes(), new LaunchedBases());
    }

    ForwardCapture open() {
        return captures.open();
    }

    Optional<String> keep(ForwardCapture capture, String scannerBody, String forwardedBody) {
        Optional<String> id = capture.chosenFor(forwardedBody).map(store::put);
        if (id.isPresent() && launchedBases.claimFirstSend(scannerBody)) {
            store.keepBase(id.get());
        }
        return id;
    }
}
