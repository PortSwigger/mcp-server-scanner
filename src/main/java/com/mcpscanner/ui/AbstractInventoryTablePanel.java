package com.mcpscanner.ui;

import com.mcpscanner.client.ListOutcome;
import com.mcpscanner.scan.ScanMode;
import com.mcpscanner.ui.detail.DetailSession;
import com.mcpscanner.ui.sendto.SendToBinding;
import com.mcpscanner.ui.widgets.SteadySelectionColours;
import com.mcpscanner.ui.widgets.SwingHtmlGuard;

import javax.swing.JComponent;
import javax.swing.JPanel;
import javax.swing.JPopupMenu;
import javax.swing.JTable;
import javax.swing.ListSelectionModel;
import javax.swing.event.ListSelectionEvent;
import javax.swing.table.TableColumn;
import java.awt.BorderLayout;
import java.util.List;
import java.util.Optional;
import java.util.function.Supplier;

public abstract class AbstractInventoryTablePanel<T, D extends InventoryDetailPanel<T>> extends JPanel {

    private static final int SELECT_COLUMN_WIDTH = 60;

    private final SelectableInventoryTableModel<T> model;
    private final JTable table;
    private final D detail;
    private final InventoryRowPopup<T> rowPopup;
    private final InventoryView view;
    private final ListStatusBanner listStatus;

    protected AbstractInventoryTablePanel() {
        this(InventoryTicks.SCAN_SELECTION, List.of());
    }

    protected AbstractInventoryTablePanel(InventoryTicks ticks, List<JComponent> toolbarActions) {
        super(new BorderLayout());
        this.model = createTableModel();
        this.table = SteadySelectionColours.install(new JTable(model));
        this.detail = createDetailPanel(ticks);
        this.rowPopup = new InventoryRowPopup<>(table, model);
        this.listStatus = new ListStatusBanner(listMethod());
        this.view = new InventoryView(table, model, detail.component(), itemNoun() + "s",
                filterSubject(), toolbarActions, ticks);

        configureSelectColumn(ticks);
        SwingHtmlGuard.guardStringColumns(table);
        table.getSelectionModel().addListSelectionListener(this::onSelectionChanged);

        add(listStatus, BorderLayout.NORTH);
        add(view, BorderLayout.CENTER);
    }

    protected abstract SelectableInventoryTableModel<T> createTableModel();

    protected abstract D createDetailPanel(InventoryTicks ticks);

    protected abstract String itemNoun();

    protected abstract String listMethod();

    protected String filterSubject() {
        return "name";
    }

    protected void onPopulated(List<T> items) {
    }

    public final void populate(List<T> items) {
        populate(ListOutcome.complete(items));
    }

    public final void populate(ListOutcome<T> outcome) {
        model.populate(outcome.items());
        detail.clear();
        listStatus.show(outcome);
        view.setListFailed(outcome.error().isPresent());
        onPopulated(outcome.items());
    }

    public final void setAvailability(InventoryView.Availability availability) {
        view.setAvailability(availability);
        rowPopup.refreshShortcuts();
        refreshDetailActions();
    }

    public final void setSendTo(SendToBinding<T> binding) {
        rowPopup.setSendTo(binding, view);
        detail.bindSendTo(binding);
    }

    final void setScan(ScanItemBinding<T> binding, Supplier<ScanMode> mode) {
        detail.bindScan(binding, mode);
    }

    final void useSession(DetailSession session) {
        detail.useSession(session);
    }

    public final void refreshDetailActions() {
        detail.refreshActions();
    }

    final SelectableInventoryTableModel<T> getTableModel() {
        return model;
    }

    final JTable table() {
        return table;
    }

    final InventoryView view() {
        return view;
    }

    final D detailPanel() {
        return detail;
    }

    final ListStatusBanner listStatus() {
        return listStatus;
    }

    final JPopupMenu rowMenu(int viewRow) {
        return rowPopup.menuForViewRow(viewRow);
    }

    private void configureSelectColumn(InventoryTicks ticks) {
        TableColumn selectColumn = table.getColumnModel().getColumn(SelectableInventoryTableModel.SELECT_COLUMN_INDEX);
        if (ticks.shown()) {
            selectColumn.setMaxWidth(SELECT_COLUMN_WIDTH);
            selectColumn.setCellRenderer(new TickableCellRenderer(table.getDefaultRenderer(Boolean.class)));
        } else {
            table.removeColumn(selectColumn);
        }
    }

    private void onSelectionChanged(ListSelectionEvent event) {
        if (!event.getValueIsAdjusting()) {
            updateDetail();
        }
    }

    private void updateDetail() {
        selectedItem().ifPresentOrElse(detail::show, detail::clear);
    }

    private Optional<T> selectedItem() {
        ListSelectionModel selection = table.getSelectionModel();
        if (selection.isSelectionEmpty()
                || selection.getMinSelectionIndex() != selection.getMaxSelectionIndex()) {
            return Optional.empty();
        }
        return Optional.ofNullable(model.rowAt(table.convertRowIndexToModel(selection.getMinSelectionIndex())));
    }
}
