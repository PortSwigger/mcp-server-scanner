package com.mcpscanner.scan;

interface EndPoller {

    void pollLater(Runnable poll);

    void shutdown();
}
