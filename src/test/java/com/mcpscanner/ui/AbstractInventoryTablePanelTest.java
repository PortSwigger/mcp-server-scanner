package com.mcpscanner.ui;

import org.junit.jupiter.api.Test;

import javax.swing.JComponent;
import javax.swing.JPanel;
import javax.swing.table.AbstractTableModel;
import java.util.ArrayList;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

class AbstractInventoryTablePanelTest {

    private final StubTableModel stubModel = new StubTableModel();
    private final StubDetailPanel stubDetail = new StubDetailPanel();
    private final AbstractInventoryTablePanel<String> panel = new AbstractInventoryTablePanel<>() {
        @Override
        protected InventoryTableModel<String> createTableModel() {
            return stubModel;
        }

        @Override
        protected InventoryDetailPanel<String> createDetailPanel() {
            return stubDetail;
        }
    };

    @Test
    void populateFiresModelUpdate() {
        panel.populate(List.of("a", "b", "c"));

        assertThat(stubModel.getRowCount()).isEqualTo(3);
    }

    @Test
    void populateClearsDetailPanel() {
        panel.populate(List.of("a", "b"));
        panel.getTableForTest().setRowSelectionInterval(0, 0);
        int clearCallsBefore = stubDetail.clearCalls;

        panel.populate(List.of());

        assertThat(stubDetail.clearCalls).isGreaterThan(clearCallsBefore);
    }

    @Test
    void singleRowSelectionRendersDetail() {
        panel.populate(List.of("alpha", "beta", "gamma"));

        panel.getTableForTest().setRowSelectionInterval(1, 1);

        assertThat(stubDetail.lastShown).isEqualTo("beta");
    }

    @Test
    void multiRowSelectionLeavesDetailEmpty() {
        panel.populate(List.of("alpha", "beta"));
        stubDetail.reset();

        panel.getTableForTest().setRowSelectionInterval(0, 1);

        assertThat(stubDetail.lastShown).isNull();
        assertThat(stubDetail.clearCalls).isGreaterThan(0);
    }

    @Test
    void selectionEventAdjustingIgnored() {
        panel.populate(List.of("alpha"));
        stubDetail.reset();

        panel.getTableForTest().getSelectionModel().setValueIsAdjusting(true);
        panel.getTableForTest().getSelectionModel().setSelectionInterval(0, 0);

        assertThat(stubDetail.lastShown).isNull();
        assertThat(stubDetail.clearCalls).isZero();
    }

    private static final class StubTableModel extends AbstractTableModel implements InventoryTableModel<String> {

        private final List<String> rows = new ArrayList<>();

        @Override
        public int getRowCount() {
            return rows.size();
        }

        @Override
        public int getColumnCount() {
            return 1;
        }

        @Override
        public Object getValueAt(int row, int column) {
            return rows.get(row);
        }

        @Override
        public String rowAt(int modelRow) {
            if (modelRow < 0 || modelRow >= rows.size()) {
                return null;
            }
            return rows.get(modelRow);
        }

        @Override
        public void populate(List<String> items) {
            rows.clear();
            rows.addAll(items);
            fireTableDataChanged();
        }
    }

    private static final class StubDetailPanel implements InventoryDetailPanel<String> {

        private final JPanel root = new JPanel();
        private String lastShown;
        private int clearCalls;

        @Override
        public JComponent component() {
            return root;
        }

        @Override
        public void show(String item) {
            lastShown = item;
        }

        @Override
        public void clear() {
            lastShown = null;
            clearCalls++;
        }

        void reset() {
            lastShown = null;
            clearCalls = 0;
        }
    }
}
