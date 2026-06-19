package com.mcpscanner.ui.widgets;

import com.mcpscanner.config.ExtensionConfigStore.PersistedScope;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class ScopeTableModelTest {

    @Test
    void addsCustomScopeEnabledByDefault() {
        ScopeTableModel model = new ScopeTableModel();

        model.addCustomScope("read:projects");

        assertThat(model.getRowCount()).isEqualTo(1);
        assertThat(model.scopeAt(0).name()).isEqualTo("read:projects");
        assertThat(model.scopeAt(0).source()).isEqualTo("custom");
        assertThat(model.scopeAt(0).enabled()).isTrue();
    }

    @Test
    void doesNotDuplicateExistingCustomScope() {
        ScopeTableModel model = new ScopeTableModel();
        model.addCustomScope("read");
        model.addCustomScope("read");

        assertThat(model.getRowCount()).isEqualTo(1);
    }

    @Test
    void removesCustomRowButRefusesDiscovered() {
        ScopeTableModel model = new ScopeTableModel();
        model.replaceDiscovered(List.of("a"));
        model.addCustomScope("b");

        model.removeRow(1);
        assertThat(model.scopeNames()).containsExactly("a");

        assertThatThrownBy(() -> model.removeRow(0))
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("custom");
    }

    @Test
    void replaceDiscoveredPreservesCustomRows() {
        ScopeTableModel model = new ScopeTableModel();
        model.replaceDiscovered(List.of("a", "b"));
        model.addCustomScope("custom1");

        model.replaceDiscovered(List.of("c"));

        assertThat(model.scopeNames()).containsExactly("c", "custom1");
    }

    @Test
    void enabledScopesReturnsOnlyChecked() {
        ScopeTableModel model = new ScopeTableModel();
        model.replaceDiscovered(List.of("a", "b"));
        model.setEnabled(0, false);

        assertThat(model.enabledScopes()).containsExactly("b");
    }

    @Test
    void setValueAtTogglesEnabledColumn() {
        ScopeTableModel model = new ScopeTableModel();
        model.replaceDiscovered(List.of("a"));

        model.setValueAt(Boolean.FALSE, 0, 0);

        assertThat(model.enabledScopes()).isEmpty();
        assertThat(model.scopeAt(0).enabled()).isFalse();
    }

    @Test
    void seedFromPersistedRoundTrips() {
        ScopeTableModel model = new ScopeTableModel();
        model.seed(List.of(
                new PersistedScope("a", true, "discovered"),
                new PersistedScope("custom1", false, "custom")));

        assertThat(model.scopeNames()).containsExactly("a", "custom1");
        assertThat(model.scopeAt(1).enabled()).isFalse();
        assertThat(model.scopeAt(1).source()).isEqualTo("custom");
    }
}
