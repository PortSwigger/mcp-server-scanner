package com.mcpscanner.ui;

import com.mcpscanner.ui.widgets.DocumentChanges;
import com.mcpscanner.ui.widgets.Placeholders;
import com.mcpscanner.ui.widgets.WholeRowScrollPane;
import com.mcpscanner.ui.widgets.WrapLayout;

import javax.swing.AbstractAction;
import javax.swing.BorderFactory;
import javax.swing.KeyStroke;
import javax.swing.JComponent;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JSplitPane;
import javax.swing.JTable;
import javax.swing.JTextField;
import javax.swing.RowFilter;
import javax.swing.table.TableModel;
import javax.swing.table.TableRowSorter;
import java.awt.BorderLayout;
import java.awt.CardLayout;
import java.awt.Dimension;
import java.awt.FlowLayout;
import java.awt.event.ActionEvent;
import java.awt.event.ComponentAdapter;
import java.awt.event.ComponentEvent;
import java.awt.event.KeyEvent;
import java.util.List;
import java.util.Locale;
import java.util.Optional;

final class InventoryView extends JPanel {

    enum Availability { DISCONNECTED, CONNECTING, CONNECTION_FAILED, CONNECTED }

    private static final String TABLE_CARD = "table";
    private static final String MESSAGE_CARD = "message";
    private static final int FILTER_COLUMNS = 16;
    private static final int GAP = 8;
    private static final double TABLE_SHARE = 0.6;

    private final JTable table;
    private final SelectableInventoryTableModel<?> model;
    private final String plural;
    private final String filterSubject;
    private final TableRowSorter<TableModel> sorter;
    private final JTextField filterField = new JTextField(FILTER_COLUMNS);
    private final List<JComponent> extraActions;
    private final InventoryTicks ticks;
    private final Optional<SelectAllHeader> selectAllHeader;
    private final CardLayout tableCards = new CardLayout();
    private final JPanel tableArea = new JPanel(tableCards);
    private final JLabel emptyLabel = messageLabel();
    private final JComponent detail;
    private final JSplitPane split = new JSplitPane(JSplitPane.VERTICAL_SPLIT);
    private final JPanel body = new JPanel(new BorderLayout());
    private Availability availability = Availability.DISCONNECTED;
    private boolean listFailed;

    InventoryView(JTable table, SelectableInventoryTableModel<?> model, JComponent detail,
                  String plural, String filterSubject, List<JComponent> extraActions, InventoryTicks ticks) {
        super(new BorderLayout());
        setBorder(BorderFactory.createEmptyBorder(0, GAP, GAP, GAP));
        this.table = table;
        this.model = model;
        this.plural = plural;
        this.filterSubject = filterSubject;
        this.extraActions = List.copyOf(extraActions);
        this.ticks = ticks;
        this.sorter = new TableRowSorter<>(model);
        table.setRowSorter(sorter);
        this.selectAllHeader = ticks.shown() ? Optional.of(new SelectAllHeader(table, model,
                SelectableInventoryTableModel.SELECT_COLUMN_INDEX, plural)) : Optional.empty();
        selectAllHeader.ifPresent(SelectAllHeader::install);
        tableArea.add(selectionFollowingScrollPane(), TABLE_CARD);
        tableArea.add(emptyLabel, MESSAGE_CARD);
        this.detail = detail;
        add(toolbar(), BorderLayout.NORTH);
        configureSplit();
        body.add(tableArea, BorderLayout.CENTER);
        add(body, BorderLayout.CENTER);
        wire();
        refresh();
    }

    void setAvailability(Availability availability) {
        this.availability = availability;
        refresh();
    }

    void setListFailed(boolean listFailed) {
        this.listFailed = listFailed;
        refresh();
    }

    void disableSorting(int modelColumn) {
        sorter.setSortable(modelColumn, false);
    }

    JTextField filterField() {
        return filterField;
    }

    SelectAllHeader selectAllHeader() {
        return selectAllHeader.orElseThrow();
    }

    String emptyMessage() {
        return emptyLabel.getText();
    }

    boolean showingDetail() {
        return split.getParent() == body;
    }

    boolean showingPlaceholder() {
        return emptyLabel.isVisible();
    }

    private void wire() {
        filterField.getDocument().addDocumentListener(DocumentChanges.onChange(this::applyFilter));
        model.addTableModelListener(event -> refresh());
        if (ticks.shown()) {
            bindKey(KeyStroke.getKeyStroke(KeyEvent.VK_SPACE, 0), "toggleTick", this::toggleSelectedRows);
        }
        table.getSelectionModel().addListSelectionListener(event -> {
            if (!event.getValueIsAdjusting()) {
                refreshDetail();
            }
        });
    }

    private JScrollPane selectionFollowingScrollPane() {
        JScrollPane scrollPane = new WholeRowScrollPane(table);
        scrollPane.addComponentListener(new ComponentAdapter() {
            @Override
            public void componentResized(ComponentEvent event) {
                revealSelectedRow();
            }
        });
        return scrollPane;
    }

    private void revealSelectedRow() {
        if (table.getSelectedRowCount() == 1) {
            table.scrollRectToVisible(table.getCellRect(table.getSelectedRow(), 0, true));
        }
    }

    private JPanel toolbar() {
        JPanel bar = new JPanel(new WrapLayout(FlowLayout.LEADING, GAP / 2, GAP / 2));
        filterField.putClientProperty("JTextField.placeholderText", "Filter by " + filterSubject);
        filterField.putClientProperty("JTextField.showClearButton", true);
        filterField.getAccessibleContext().setAccessibleName("Filter " + plural);
        filterField.setToolTipText("Show only " + plural + " whose " + filterSubject + " contains this");
        filterField.setMaximumSize(filterField.getPreferredSize());
        filterField.setMinimumSize(filterField.getPreferredSize());
        bar.add(filterField);
        extraActions.forEach(bar::add);
        return bar;
    }

    private void configureSplit() {
        split.setResizeWeight(TABLE_SHARE);
        split.setBorder(null);
        split.addComponentListener(new ComponentAdapter() {
            private boolean placed;

            @Override
            public void componentResized(ComponentEvent event) {
                if (!placed && split.getHeight() > 0) {
                    split.setDividerLocation(TABLE_SHARE);
                    placed = true;
                }
            }
        });
        tableArea.setMinimumSize(new Dimension(0, 0));
        detail.setMinimumSize(new Dimension(0, 0));
    }

    private void bindKey(KeyStroke key, String name, Runnable action) {
        table.getInputMap(JComponent.WHEN_FOCUSED).put(key, name);
        table.getActionMap().put(name, new AbstractAction() {
            @Override
            public void actionPerformed(ActionEvent event) {
                action.run();
            }
        });
    }

    private void toggleSelectedRows() {
        int[] viewRows = table.getSelectedRows();
        if (viewRows.length == 0) {
            return;
        }
        boolean ticked = !isTicked(table.convertRowIndexToModel(viewRows[0]));
        for (int viewRow : viewRows) {
            setTicked(table.convertRowIndexToModel(viewRow), ticked);
        }
        for (int viewRow : viewRows) {
            table.addRowSelectionInterval(viewRow, viewRow);
        }
    }

    private void applyFilter() {
        String needle = filterField.getText().trim().toLowerCase(Locale.ROOT);
        sorter.setRowFilter(needle.isEmpty() ? null : new ContainsFilter(model, needle));
        refresh();
    }

    private boolean isTicked(int modelRow) {
        return Boolean.TRUE.equals(model.getValueAt(modelRow, SelectableInventoryTableModel.SELECT_COLUMN_INDEX));
    }

    private void setTicked(int modelRow, boolean ticked) {
        model.setValueAt(ticked, modelRow, SelectableInventoryTableModel.SELECT_COLUMN_INDEX);
    }

    private void refresh() {
        boolean hasRows = model.getRowCount() > 0;
        boolean usable = availability == Availability.CONNECTED && hasRows;
        filterField.setEnabled(usable);
        selectAllHeader.ifPresent(header -> header.setEnabled(usable));
        extraActions.forEach(action -> action.setVisible(usable));
        boolean empty = table.getRowCount() == 0;
        emptyLabel.setText(emptyText(hasRows));
        tableCards.show(tableArea, empty ? MESSAGE_CARD : TABLE_CARD);
        refreshDetail();
    }

    private String emptyText(boolean hasRows) {
        if (hasRows) {
            return "No " + plural + " match “" + filterField.getText().trim() + "”." + tickedOutsideFilterNote();
        }
        return switch (availability) {
            case CONNECTED -> listFailed
                    ? "The server couldn't list its " + plural + ". The message above says why."
                    : "This server exposes no " + plural + ".";
            case CONNECTING -> "Connecting… " + plural + " appear here once connected.";
            case CONNECTION_FAILED -> "The last connection attempt failed. The status line and the Log panel on the right say why.";
            case DISCONNECTED -> "Connect to list the server's " + plural + ".";
        };
    }

    private String tickedOutsideFilterNote() {
        return ticks.shown() ? " Ticked " + plural + " outside the filter are still scanned." : "";
    }

    private void refreshDetail() {
        boolean wanted = table.getSelectedRowCount() == 1;
        if (wanted != showingDetail()) {
            showBody(wanted ? splitWithDetail() : tableArea);
        }
    }

    private JSplitPane splitWithDetail() {
        split.setTopComponent(tableArea);
        split.setBottomComponent(detail);
        return split;
    }

    private void showBody(JComponent content) {
        body.removeAll();
        body.add(content, BorderLayout.CENTER);
        body.revalidate();
        body.repaint();
    }

    private static JLabel messageLabel() {
        return Placeholders.centred("");
    }

    private static final class ContainsFilter extends RowFilter<TableModel, Integer> {
        private final SelectableInventoryTableModel<?> model;
        private final String needle;

        private ContainsFilter(SelectableInventoryTableModel<?> model, String needle) {
            this.model = model;
            this.needle = needle;
        }

        @Override
        public boolean include(Entry<? extends TableModel, ? extends Integer> entry) {
            return model.filterTextAt(entry.getIdentifier()).toLowerCase(Locale.ROOT).contains(needle);
        }
    }
}
