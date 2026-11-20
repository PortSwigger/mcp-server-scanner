package com.mcpscanner.auth.oauth;

import java.io.IOException;

@FunctionalInterface
public interface CallbackListenerFactory {

    CallbackListener start(String host, int port, String path) throws IOException;

    default CallbackListener start(int port, String path) throws IOException {
        return start(CallbackListener.LOOPBACK_HOST, port, path);
    }

    static CallbackListenerFactory defaultFactory() {
        return new ActiveCallbackListeners();
    }
}
