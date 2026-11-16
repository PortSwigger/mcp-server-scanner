package com.mcpscanner.proxy;

import com.mcpscanner.logging.McpEventLog;
import com.mcpscanner.mcp.LegacySseRoutes;

import java.util.Optional;

public record UpstreamRecording(UpstreamCaptures captures, UpstreamExchangeStore store,
                                LegacySseRoutes legacySseRoutes) {

    public static UpstreamRecording create() {
        return create(McpEventLog.noop());
    }

    public static UpstreamRecording create(McpEventLog eventLog) {
        return new UpstreamRecording(new UpstreamCaptures(), new UpstreamExchangeStore(eventLog),
                new LegacySseRoutes());
    }

    ForwardCapture open() {
        return captures.open();
    }

    Optional<String> keep(ForwardCapture capture, String forwardedBody) {
        return capture.chosenFor(forwardedBody).map(store::put);
    }
}
