package com.mcpscanner;

import burp.api.montoya.extension.ExtensionUnloadingHandler;

import java.util.List;
import java.util.Objects;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.function.Consumer;

final class ShutdownHooks implements ExtensionUnloadingHandler {

    private record Hook(String name, Runnable action) {}

    private final List<Hook> hooks = new CopyOnWriteArrayList<>();
    private final Consumer<String> failureSink;

    ShutdownHooks(Consumer<String> failureSink) {
        this.failureSink = Objects.requireNonNull(failureSink);
    }

    void add(String name, Runnable action) {
        hooks.add(new Hook(Objects.requireNonNull(name), Objects.requireNonNull(action)));
    }

    List<String> names() {
        return hooks.stream().map(Hook::name).toList();
    }

    @Override
    public void extensionUnloaded() {
        hooks.forEach(this::runGuarded);
    }

    private void runGuarded(Hook hook) {
        try {
            hook.action().run();
        } catch (RuntimeException failure) {
            failureSink.accept("Shutdown step '" + hook.name() + "' failed: "
                    + failure.getClass().getSimpleName() + ": " + failure.getMessage());
        }
    }
}
