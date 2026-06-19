package com.mcpscanner.auth.oauth;

import java.io.IOException;

@FunctionalInterface
public interface CallbackListenerFactory {

    CallbackListener start(int port, String path) throws IOException;

    static CallbackListenerFactory defaultFactory() {
        return CallbackListener::start;
    }
}
