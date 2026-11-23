package com.mcpscanner.ui;

import com.mcpscanner.scan.ScanMode;
import org.junit.jupiter.api.Test;

import javax.swing.JComponent;
import javax.swing.JPanel;
import java.util.ArrayList;
import java.util.List;
import java.util.function.Supplier;

import static org.assertj.core.api.Assertions.assertThat;

class AbstractInventoryTablePanelTest {

    private final StubTableModel stubModel = new StubTableModel();
    private final StubDetailPanel stubDetail = new StubDetailPanel();
    private final AbstractInventoryTablePanel<String, StubDetailPanel> panel = new AbstractInventoryTablePanel<>() {
        @Override
        protected SelectableInventoryTableModel<String> createTableModel() {
            return stubModel;
        }

        @Override
        protected String itemNoun() {
            return "item";
        }

        @Override
        protected String listMethod() {
            return "items/list";
        }

        @Override
        protected StubDetailPanel createDetailPanel(InventoryTicks ticks) {
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
        panel.table().setRowSelectionInterval(0, 0);
        int clearCallsBefore = stubDetail.clearCalls;

        panel.populate(List.of());

        assertThat(stubDetail.clearCalls).isGreaterThan(clearCallsBefore);
    }

    @Test
    void singleRowSelectionRendersDetail() {
        panel.populate(List.of("alpha", "beta", "gamma"));

        panel.table().setRowSelectionInterval(1, 1);

        assertThat(stubDetail.lastShown).isEqualTo("beta");
    }

    @Test
    void multiRowSelectionLeavesDetailEmpty() {
        panel.populate(List.of("alpha", "beta"));
        stubDetail.reset();

        panel.table().setRowSelectionInterval(0, 1);

        assertThat(stubDetail.lastShown).isNull();
        assertThat(stubDetail.clearCalls).isGreaterThan(0);
    }

    @Test
    void selectionEventAdjustingIgnored() {
        panel.populate(List.of("alpha"));
        stubDetail.reset();

        panel.table().getSelectionModel().setValueIsAdjusting(true);
        panel.table().getSelectionModel().setSelectionInterval(0, 0);

        assertThat(stubDetail.lastShown).isNull();
        assertThat(stubDetail.clearCalls).isZero();
    }

    private static final class StubTableModel extends SelectableInventoryTableModel<String> {

        @Override
        protected String[] extraColumnNames() {
            return new String[] {"Value"};
        }

        @Override
        protected String filterText(String item) {
            return item;
        }

        @Override
        protected Object extraValueAt(String item, int extraColumnIndex) {
            return item;
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

        @Override
        public void bindSendTo(com.mcpscanner.ui.sendto.SendToBinding<String> binding) {
        }

        @Override
        public void bindScan(ScanItemBinding<String> binding, Supplier<ScanMode> mode) {
        }

        @Override
        public void refreshActions() {
        }

        void reset() {
            lastShown = null;
            clearCalls = 0;
        }
    }
}
