package com.mcpscanner.scan;

import com.mcpscanner.config.ExtensionConfigStore;
import com.mcpscanner.scan.request.RequestFamily;
import com.mcpscanner.scan.request.RequestFamilyToggles;

import java.util.Objects;
import java.util.concurrent.CopyOnWriteArrayList;

public final class ScanGenerationSettings implements RequestFamilyToggles {

    private final ExtensionConfigStore configStore;
    private final CopyOnWriteArrayList<Runnable> familyListeners = new CopyOnWriteArrayList<>();

    public ScanGenerationSettings(ExtensionConfigStore configStore) {
        this.configStore = configStore;
    }

    @Override
    public boolean isEnabled(RequestFamily family) {
        return !Boolean.FALSE.equals(configStore.requestFamilyEnabled(family.id()));
    }

    public void setEnabled(RequestFamily family, boolean enabled) {
        configStore.setRequestFamilyEnabled(family.id(), enabled);
        familyListeners.forEach(Runnable::run);
    }

    public void addFamilyListener(Runnable listener) {
        familyListeners.add(Objects.requireNonNull(listener));
    }

    public void removeFamilyListener(Runnable listener) {
        familyListeners.remove(listener);
    }

    public boolean headerFieldsEnabled() {
        return !Boolean.FALSE.equals(configStore.headerFieldsEnabled());
    }

    public void setHeaderFieldsEnabled(boolean enabled) {
        configStore.setHeaderFieldsEnabled(enabled);
    }

    public boolean metaEnvelopeFuzzedOnEveryRequest() {
        return Boolean.TRUE.equals(configStore.metaEnvelopeFuzzedOnEveryRequest());
    }

    public void setMetaEnvelopeFuzzedOnEveryRequest(boolean enabled) {
        configStore.setMetaEnvelopeFuzzedOnEveryRequest(enabled);
    }
}
