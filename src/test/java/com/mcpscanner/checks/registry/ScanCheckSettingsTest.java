package com.mcpscanner.checks.registry;

import com.mcpscanner.config.ExtensionConfigStore;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.ArrayList;
import java.util.List;
import java.util.function.BiConsumer;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoMoreInteractions;
import static org.mockito.Mockito.when;

class ScanCheckSettingsTest {

    private ExtensionConfigStore store;
    private ScanCheckSettings settings;

    @BeforeEach
    void setUp() {
        store = mock(ExtensionConfigStore.class);
        settings = new ScanCheckSettings(store);
    }

    @Test
    void returnsStoredTrueValue() {
        when(store.checkEnabled("tool-enum")).thenReturn(true);

        assertThat(settings.isEnabled("tool-enum", false)).isTrue();
    }

    @Test
    void returnsStoredFalseValue() {
        when(store.checkEnabled("tool-enum")).thenReturn(false);

        assertThat(settings.isEnabled("tool-enum", true)).isFalse();
    }

    @Test
    void fallsBackToDefaultAndCachesWhenStoreReturnsNull() {
        when(store.checkEnabled("tool-enum")).thenReturn(null);

        assertThat(settings.isEnabled("tool-enum", true)).isTrue();
        assertThat(settings.isEnabled("tool-enum", true)).isTrue();
        assertThat(settings.isEnabled("tool-enum", true)).isTrue();

        verify(store, times(1)).checkEnabled("tool-enum");
    }

    @Test
    void setEnabledWritesThroughAndUpdatesCache() {
        when(store.checkEnabled("schema-bypass")).thenReturn(false);
        assertThat(settings.isEnabled("schema-bypass", false)).isFalse();

        settings.setEnabled("schema-bypass", true);

        assertThat(settings.isEnabled("schema-bypass", false)).isTrue();
        verify(store).setCheckEnabled("schema-bypass", true);
        verify(store, times(1)).checkEnabled("schema-bypass");
    }

    @Test
    void setEnabledNotifiesListeners() {
        List<String> seenIds = new ArrayList<>();
        List<Boolean> seenValues = new ArrayList<>();
        BiConsumer<String, Boolean> listener = (id, enabled) -> {
            seenIds.add(id);
            seenValues.add(enabled);
        };
        settings.addListener(listener);

        settings.setEnabled("auth-bypass", true);
        settings.setEnabled("auth-bypass", false);

        assertThat(seenIds).containsExactly("auth-bypass", "auth-bypass");
        assertThat(seenValues).containsExactly(true, false);
    }

    @Test
    void removedListenerNoLongerInvoked() {
        List<String> seenIds = new ArrayList<>();
        BiConsumer<String, Boolean> listener = (id, enabled) -> seenIds.add(id);
        settings.addListener(listener);
        settings.removeListener(listener);

        settings.setEnabled("tool-enum", true);

        assertThat(seenIds).isEmpty();
    }

    @Test
    void cacheIsKeyedById() {
        when(store.checkEnabled("a")).thenReturn(true);
        when(store.checkEnabled("b")).thenReturn(false);

        assertThat(settings.isEnabled("a", false)).isTrue();
        assertThat(settings.isEnabled("b", true)).isFalse();

        verify(store).checkEnabled("a");
        verify(store).checkEnabled("b");
        verifyNoMoreInteractions(store);
    }
}
