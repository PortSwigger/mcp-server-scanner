package com.mcpscanner.auth.oauth;

import java.io.IOException;
import java.util.concurrent.atomic.AtomicInteger;

final class EphemeralCallbackListeners implements CallbackListenerFactory {

    private static final int EPHEMERAL = 0;

    private final AtomicInteger requestedPort = new AtomicInteger();
    private final AtomicInteger boundPort = new AtomicInteger();

    @Override
    public CallbackListener start(String host, int requestedPort, String path) throws IOException {
        this.requestedPort.set(requestedPort);
        CallbackListener listener = CallbackListener.start(host, EPHEMERAL, path);
        boundPort.set(listener.port());
        return listener;
    }

    int requestedPort() {
        return requestedPort.get();
    }

    int boundPort() {
        return boundPort.get();
    }
}
