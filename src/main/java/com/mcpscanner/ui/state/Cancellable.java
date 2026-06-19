package com.mcpscanner.ui.state;

@FunctionalInterface
public interface Cancellable {

    Cancellable NOOP = () -> { };

    void cancel();
}
