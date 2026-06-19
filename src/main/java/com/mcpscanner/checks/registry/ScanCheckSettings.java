package com.mcpscanner.checks.registry;

import com.mcpscanner.config.ExtensionConfigStore;

import java.util.Objects;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.function.BiConsumer;

public final class ScanCheckSettings {

    private final ExtensionConfigStore store;
    private final ConcurrentMap<String, Boolean> cache = new ConcurrentHashMap<>();
    private final CopyOnWriteArrayList<BiConsumer<String, Boolean>> listeners = new CopyOnWriteArrayList<>();

    public ScanCheckSettings(ExtensionConfigStore store) {
        this.store = Objects.requireNonNull(store, "store must not be null");
    }

    public boolean isEnabled(String id, boolean defaultValue) {
        return cache.computeIfAbsent(id, key -> {
            Boolean stored = store.checkEnabled(key);
            return stored != null ? stored : defaultValue;
        });
    }

    public void setEnabled(String id, boolean enabled) {
        cache.put(id, enabled);
        store.setCheckEnabled(id, enabled);
        for (BiConsumer<String, Boolean> listener : listeners) {
            listener.accept(id, enabled);
        }
    }

    public void addListener(BiConsumer<String, Boolean> listener) {
        listeners.add(Objects.requireNonNull(listener, "listener must not be null"));
    }

    public void removeListener(BiConsumer<String, Boolean> listener) {
        listeners.remove(listener);
    }
}
