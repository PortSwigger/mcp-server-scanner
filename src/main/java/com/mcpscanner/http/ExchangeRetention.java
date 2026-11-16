package com.mcpscanner.http;

@FunctionalInterface
public interface ExchangeRetention {

    ExchangeRetention NONE = () -> {
    };

    void release();
}
