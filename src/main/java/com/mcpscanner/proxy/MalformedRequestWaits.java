package com.mcpscanner.proxy;

import com.mcpscanner.logging.McpEventLog;

import java.time.Duration;
import java.util.concurrent.atomic.AtomicBoolean;

final class MalformedRequestWaits {

    static final Duration DEFAULT_SHORT_WAIT = Duration.ofSeconds(2);

    private final Duration shortWait;
    private final AtomicBoolean serverLeavesThemUnanswered = new AtomicBoolean();

    MalformedRequestWaits(Duration shortWait) {
        this.shortWait = shortWait;
    }

    Duration timeout(Duration fullWait) {
        return serverLeavesThemUnanswered.get() ? shortWait : fullWait;
    }

    void answered() {
        serverLeavesThemUnanswered.set(false);
    }

    void unanswered(McpEventLog eventLog) {
        if (!serverLeavesThemUnanswered.getAndSet(true)) {
            eventLog.info("SSE server left a malformed JSON-RPC request without a reply carrying its id; "
                    + "further malformed requests wait " + shortWait.toSeconds() + " s until one is answered");
        }
    }
}
