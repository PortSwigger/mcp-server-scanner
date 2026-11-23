package com.mcpscanner.config;

import java.util.List;
import java.util.Objects;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.function.Consumer;

public final class SignedInConsentSetting {

    private final ExtensionConfigStore configStore;
    private final List<Consumer<Boolean>> listeners = new CopyOnWriteArrayList<>();

    public SignedInConsentSetting(ExtensionConfigStore configStore) {
        this.configStore = Objects.requireNonNull(configStore, "configStore must not be null");
    }

    public boolean optedIn() {
        return configStore.signedInConsentOptedIn();
    }

    public void optIn(boolean optedIn) {
        configStore.setSignedInConsentOptedIn(optedIn);
        listeners.forEach(listener -> listener.accept(optedIn));
    }

    public void addListener(Consumer<Boolean> listener) {
        listeners.add(Objects.requireNonNull(listener, "listener must not be null"));
    }

    public void removeListener(Consumer<Boolean> listener) {
        listeners.remove(listener);
    }
}
