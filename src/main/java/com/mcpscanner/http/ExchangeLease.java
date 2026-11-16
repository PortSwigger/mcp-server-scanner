package com.mcpscanner.http;

import burp.api.montoya.http.message.HttpRequestResponse;

public interface ExchangeLease extends AutoCloseable {

    ExchangeLease NONE = new ExchangeLease() {
        @Override
        public ExchangeRetention retainBeyondClose() {
            return ExchangeRetention.NONE;
        }

        @Override
        public void hold(HttpRequestResponse proxied) {
        }

        @Override
        public void close() {
        }
    };

    void hold(HttpRequestResponse proxied);

    ExchangeRetention retainBeyondClose();

    @Override
    void close();
}
