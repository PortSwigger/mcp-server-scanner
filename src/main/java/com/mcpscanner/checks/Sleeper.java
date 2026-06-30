package com.mcpscanner.checks;

import java.time.Duration;

@FunctionalInterface
public interface Sleeper {

    Sleeper SYSTEM = duration -> {
        try {
            Thread.sleep(duration.toMillis());
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
    };

    void sleep(Duration duration);
}
