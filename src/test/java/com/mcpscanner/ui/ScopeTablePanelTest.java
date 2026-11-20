package com.mcpscanner.ui;

import com.mcpscanner.config.ExtensionConfigStore.PersistedScope;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.stream.IntStream;

import static org.assertj.core.api.Assertions.assertThat;

class ScopeTablePanelTest {

    private final ScopeTablePanel panel = new ScopeTablePanel();

    @Test
    void showsEnabledScopeAndSourceWithNoEmptyColumn() {
        assertThat(IntStream.range(0, panel.table().getColumnCount()).mapToObj(panel.table()::getColumnName))
                .containsExactly("Enabled", "Scope", "Source");
    }

    @Test
    void theScopeColumnTakesTheSpareWidth() {
        panel.table().setSize(400, 100);
        panel.table().doLayout();

        int scope = panel.table().getColumnModel().getColumn(ScopeTableModel.COLUMN_NAME).getWidth();
        assertThat(scope).isGreaterThan(200);
    }

    @Test
    void aLockedTableRefusesEveryEdit() {
        panel.seed(List.of(new PersistedScope("custom:one", true, "custom")));
        panel.table().setRowSelectionInterval(0, 0);

        panel.setLocked(true);

        assertThat(panel.table().isEnabled()).isFalse();
        assertThat(panel.removeButton().isEnabled()).isFalse();
        assertThat(panel.table().isCellEditable(0, ScopeTableModel.COLUMN_ENABLED)).isFalse();

        panel.setLocked(false);

        assertThat(panel.table().isEnabled()).isTrue();
        assertThat(panel.removeButton().isEnabled()).isTrue();
    }

    @Test
    void theRemoveButtonRemovesOnlyASelectedCustomScope() {
        panel.seed(List.of(new PersistedScope("mcp:resources", true, "discovered"),
                new PersistedScope("custom:one", true, "custom")));

        panel.table().setRowSelectionInterval(0, 0);
        assertThat(panel.removeButton().isEnabled()).isFalse();

        panel.table().setRowSelectionInterval(1, 1);
        assertThat(panel.removeButton().isEnabled()).isTrue();
        panel.removeButton().doClick();

        assertThat(panel.scopesSnapshot()).extracting(PersistedScope::source).containsOnly("discovered");
        assertThat(panel.table().getRowCount()).isEqualTo(1);
    }
}
