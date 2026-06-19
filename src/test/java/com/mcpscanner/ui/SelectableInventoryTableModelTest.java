package com.mcpscanner.ui;

import org.junit.jupiter.api.Test;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

class SelectableInventoryTableModelTest {

    private final StringSelectableModel model = new StringSelectableModel();

    @Test
    void selectColumnIsFirstWithBooleanType() {
        assertThat(model.getColumnName(0)).isEqualTo("Select");
        assertThat(model.getColumnClass(0)).isEqualTo(Boolean.class);
    }

    @Test
    void onlySelectColumnIsEditable() {
        model.populate(List.of("a"));

        assertThat(model.isCellEditable(0, 0)).isTrue();
        for (int col = 1; col < model.getColumnCount(); col++) {
            assertThat(model.isCellEditable(0, col)).isFalse();
        }
    }

    @Test
    void populateDefaultsAllRowsToSelected() {
        model.populate(List.of("a", "b", "c"));

        assertThat(model.selectedItems()).containsExactly("a", "b", "c");
        for (int row = 0; row < model.getRowCount(); row++) {
            assertThat(model.getValueAt(row, 0)).isEqualTo(Boolean.TRUE);
        }
    }

    @Test
    void deselectingRowRemovesItFromSelectedItems() {
        model.populate(List.of("a", "b", "c"));

        model.setValueAt(false, 1, 0);

        assertThat(model.selectedItems()).containsExactly("a", "c");
    }

    @Test
    void reselectingRowRestoresItToSelectedItems() {
        model.populate(List.of("a", "b"));
        model.setValueAt(false, 0, 0);

        model.setValueAt(true, 0, 0);

        assertThat(model.selectedItems()).containsExactly("a", "b");
    }

    @Test
    void rowAtReturnsUnderlyingItem() {
        model.populate(List.of("x", "y"));

        assertThat(model.rowAt(0)).isEqualTo("x");
        assertThat(model.rowAt(1)).isEqualTo("y");
    }

    @Test
    void rowAtOutOfBoundsReturnsNull() {
        model.populate(List.of("a"));

        assertThat(model.rowAt(-1)).isNull();
        assertThat(model.rowAt(5)).isNull();
    }

    @Test
    void populateReplacesPreviousRowsAndDefaultsSelected() {
        model.populate(List.of("a", "b", "c"));
        model.setValueAt(false, 0, 0);

        model.populate(List.of("x", "y"));

        assertThat(model.getRowCount()).isEqualTo(2);
        assertThat(model.selectedItems()).containsExactly("x", "y");
    }

    @Test
    void nonSelectColumnsResolvedBySubclass() {
        model.populate(List.of("hello"));

        assertThat(model.getValueAt(0, 1)).isEqualTo("hello");
        assertThat(model.getValueAt(0, 2)).isEqualTo("HELLO");
    }

    private static final class StringSelectableModel extends SelectableInventoryTableModel<String> {

        private static final String[] EXTRA_COLUMNS = {"Value", "Upper"};

        @Override
        protected String[] extraColumnNames() {
            return EXTRA_COLUMNS;
        }

        @Override
        protected Object extraValueAt(String item, int extraColumnIndex) {
            return switch (extraColumnIndex) {
                case 0 -> item;
                case 1 -> item.toUpperCase();
                default -> null;
            };
        }
    }
}
