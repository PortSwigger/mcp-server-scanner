package com.mcpscanner.ui;

import burp.api.montoya.core.ByteArray;
import burp.api.montoya.ui.UserInterface;
import burp.api.montoya.ui.editor.EditorOptions;
import burp.api.montoya.ui.editor.RawEditor;
import com.fasterxml.jackson.databind.JsonNode;
import com.mcpscanner.mcp.McpToolDefinition;
import com.mcpscanner.mcp.ToolAnnotations;
import com.mcpscanner.config.ExtensionConfigStore;
import com.mcpscanner.mcp.McpObjectMapper;
import com.mcpscanner.ui.widgets.SwingHtmlGuard;
import com.mcpscanner.ui.widgets.ThemeColors;

import javax.swing.BorderFactory;
import javax.swing.Box;
import javax.swing.BoxLayout;
import javax.swing.JButton;
import javax.swing.JCheckBox;
import javax.swing.JComponent;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JSplitPane;
import javax.swing.JTabbedPane;
import javax.swing.JTable;
import javax.swing.JTextArea;
import javax.swing.ListSelectionModel;
import javax.swing.SwingConstants;
import javax.swing.UIManager;
import javax.swing.event.ListSelectionListener;
import javax.swing.event.TableModelEvent;
import javax.swing.table.DefaultTableCellRenderer;
import javax.swing.table.JTableHeader;
import javax.swing.table.TableCellRenderer;
import javax.swing.table.TableColumn;
import java.awt.BorderLayout;
import java.awt.CardLayout;
import java.awt.Color;
import java.awt.Component;
import java.awt.Font;
import java.awt.Graphics;
import java.awt.Graphics2D;
import java.awt.RenderingHints;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.util.List;
import java.util.function.Consumer;
import java.util.function.Supplier;

public class ToolTablePanel extends JPanel {

    private static final int SELECT_COLUMN_WIDTH = 80;
    private static final int ANNOTATIONS_COLUMN_WIDTH = 130;

    private final ToolTableModel tableModel;
    private final JTable table;
    private final ToolDetailPanel detailPanel;
    private final TriStateHeaderRenderer headerRenderer;
    private final JButton selectReadOnlyButton;
    private final JButton resetWarningsButton;

    private ExtensionConfigStore configStore;
    private Supplier<String> endpointSupplier = () -> null;
    private Consumer<String> statusReporter = message -> {};
    private boolean suppressPersistence;

    public ToolTablePanel(UserInterface userInterface) {
        super(new BorderLayout());
        this.tableModel = new ToolTableModel();
        this.table = new JTable(tableModel);
        this.detailPanel = new ToolDetailPanel(userInterface);
        this.headerRenderer = new TriStateHeaderRenderer();
        this.selectReadOnlyButton = new JButton("Select read-only tools only");
        this.resetWarningsButton = new JButton("Reset scan warnings");

        configureColumns();
        SwingHtmlGuard.guardStringColumns(table);
        installSelectColumnRenderers();
        installAnnotationsColumnRenderer();
        installTriStateHeader();
        installToolbarActions();
        table.getSelectionModel().addListSelectionListener(onSelectionChanged());
        tableModel.addTableModelListener(this::onTableModelChange);

        add(buildToolbar(), BorderLayout.NORTH);
        add(buildSplitPane(), BorderLayout.CENTER);
    }

    public void populate(List<McpToolDefinition> tools) {
        tableModel.populate(tools);
        detailPanel.clear();
        applyDefaultSelections(tools);
        refreshHeader();
    }

    public List<McpToolDefinition> selectedTools() {
        return tableModel.selectedItems();
    }

    public void setSelectionPersistence(ExtensionConfigStore configStore,
                                        Supplier<String> endpointSupplier) {
        this.configStore = configStore;
        this.endpointSupplier = endpointSupplier != null ? endpointSupplier : () -> null;
    }

    public void setStatusReporter(Consumer<String> reporter) {
        this.statusReporter = reporter != null ? reporter : message -> {};
    }

    ToolTableModel getTableModel() {
        return tableModel;
    }

    ToolDetailPanel getDetailPanelForTest() {
        return detailPanel;
    }

    JTable getTableForTest() {
        return table;
    }

    JButton selectReadOnlyButtonForTest() {
        return selectReadOnlyButton;
    }

    JButton resetWarningsButtonForTest() {
        return resetWarningsButton;
    }

    HeaderState headerStateForTest() {
        return computeHeaderState();
    }

    void simulateHeaderClickForTest() {
        toggleAllSelections();
    }

    private void configureColumns() {
        TableColumn selectColumn = table.getColumnModel().getColumn(SelectableInventoryTableModel.SELECT_COLUMN_INDEX);
        selectColumn.setMaxWidth(SELECT_COLUMN_WIDTH);
        selectColumn.setMinWidth(SELECT_COLUMN_WIDTH);
        TableColumn annotationsColumn = table.getColumnModel().getColumn(ToolTableModel.COLUMN_ANNOTATIONS + 1);
        annotationsColumn.setPreferredWidth(ANNOTATIONS_COLUMN_WIDTH);
        annotationsColumn.setMaxWidth(ANNOTATIONS_COLUMN_WIDTH);
    }

    private void installSelectColumnRenderers() {
        TableColumn selectColumn = table.getColumnModel().getColumn(SelectableInventoryTableModel.SELECT_COLUMN_INDEX);
        selectColumn.setCellRenderer(new SelectCellRenderer());
    }

    private void installAnnotationsColumnRenderer() {
        TableColumn annotationsColumn = table.getColumnModel().getColumn(ToolTableModel.COLUMN_ANNOTATIONS + 1);
        annotationsColumn.setCellRenderer(new AnnotationsCellRenderer());
    }

    private void installTriStateHeader() {
        JTableHeader header = table.getTableHeader();
        TableColumn selectColumn = table.getColumnModel().getColumn(SelectableInventoryTableModel.SELECT_COLUMN_INDEX);
        selectColumn.setHeaderRenderer(headerRenderer);
        header.addMouseListener(new HeaderClickListener());
    }

    private void installToolbarActions() {
        selectReadOnlyButton.addActionListener(e -> applyReadOnlyPreset());
        resetWarningsButton.addActionListener(e -> resetWarnings());
    }

    private JPanel buildToolbar() {
        JPanel toolbar = new JPanel();
        toolbar.setLayout(new BoxLayout(toolbar, BoxLayout.LINE_AXIS));
        toolbar.setBorder(BorderFactory.createEmptyBorder(4, 8, 4, 8));
        toolbar.add(selectReadOnlyButton);
        toolbar.add(Box.createHorizontalStrut(8));
        toolbar.add(resetWarningsButton);
        toolbar.add(Box.createHorizontalGlue());
        styleSecondaryButton(resetWarningsButton);
        return toolbar;
    }

    private static void styleSecondaryButton(JButton button) {
        button.setFocusPainted(false);
        button.setContentAreaFilled(false);
        button.setBorderPainted(true);
        Font font = button.getFont();
        if (font != null) {
            button.setFont(font.deriveFont(font.getSize2D() - 1f));
        }
    }

    private JSplitPane buildSplitPane() {
        JSplitPane split = new JSplitPane(
                JSplitPane.VERTICAL_SPLIT,
                new JScrollPane(table),
                detailPanel);
        split.setResizeWeight(0.6);
        return split;
    }

    private ListSelectionListener onSelectionChanged() {
        return event -> {
            if (event.getValueIsAdjusting()) {
                return;
            }
            updateDetail();
        };
    }

    private void onTableModelChange(TableModelEvent event) {
        if (event.getType() == TableModelEvent.UPDATE
                && event.getColumn() == SelectableInventoryTableModel.SELECT_COLUMN_INDEX) {
            persistSelectionChange(event.getFirstRow());
        }
        refreshHeader();
    }

    private void persistSelectionChange(int row) {
        if (suppressPersistence || configStore == null
                || row < 0 || row >= tableModel.getRowCount()) {
            return;
        }
        String endpoint = endpointSupplier.get();
        if (endpoint == null || endpoint.isEmpty()) {
            return;
        }
        McpToolDefinition tool = tableModel.rowAt(row);
        if (tool == null) {
            return;
        }
        configStore.setToolSelected(endpoint, tool.name(), tableModel.isSelected(row));
    }

    private void applyDefaultSelections(List<McpToolDefinition> tools) {
        if (configStore == null) {
            return;
        }
        String endpoint = endpointSupplier.get();
        boolean hasEndpoint = endpoint != null && !endpoint.isEmpty();
        suppressPersistence = true;
        try {
            for (int i = 0; i < tools.size(); i++) {
                McpToolDefinition tool = tools.get(i);
                boolean selected = resolveDefaultSelection(hasEndpoint ? endpoint : null, tool);
                tableModel.setValueAt(selected, i, SelectableInventoryTableModel.SELECT_COLUMN_INDEX);
            }
        } finally {
            suppressPersistence = false;
        }
    }

    private boolean resolveDefaultSelection(String endpoint, McpToolDefinition tool) {
        if (endpoint != null) {
            Boolean stored = configStore.toolSelected(endpoint, tool.name());
            if (stored != null) {
                return stored;
            }
        }
        return tool.annotations().isExplicitlyReadOnly();
    }

    private void applyReadOnlyPreset() {
        for (int i = 0; i < tableModel.getRowCount(); i++) {
            McpToolDefinition tool = tableModel.rowAt(i);
            if (tool == null) {
                continue;
            }
            tableModel.setValueAt(tool.annotations().isExplicitlyReadOnly(), i,
                    SelectableInventoryTableModel.SELECT_COLUMN_INDEX);
        }
    }

    private void resetWarnings() {
        if (configStore == null) {
            return;
        }
        String endpoint = endpointSupplier.get();
        if (endpoint == null || endpoint.isEmpty()) {
            return;
        }
        configStore.setDontAskAgain(endpoint, false);
        statusReporter.accept("Scan warnings re-armed for " + endpoint);
    }

    private void toggleAllSelections() {
        boolean targetValue = computeHeaderState() != HeaderState.ALL;
        for (int i = 0; i < tableModel.getRowCount(); i++) {
            tableModel.setValueAt(targetValue, i, SelectableInventoryTableModel.SELECT_COLUMN_INDEX);
        }
    }

    private HeaderState computeHeaderState() {
        int total = tableModel.getRowCount();
        if (total == 0) {
            return HeaderState.NONE;
        }
        int selected = tableModel.selectedCount();
        if (selected == 0) {
            return HeaderState.NONE;
        }
        if (selected == total) {
            return HeaderState.ALL;
        }
        return HeaderState.PARTIAL;
    }

    private void refreshHeader() {
        headerRenderer.setState(computeHeaderState());
        JTableHeader header = table.getTableHeader();
        if (header != null) {
            header.repaint();
        }
    }

    private void updateDetail() {
        ListSelectionModel selection = table.getSelectionModel();
        if (selection.isSelectionEmpty()
                || selection.getMinSelectionIndex() != selection.getMaxSelectionIndex()) {
            detailPanel.clear();
            return;
        }
        int viewRow = selection.getMinSelectionIndex();
        int modelRow = table.convertRowIndexToModel(viewRow);
        McpToolDefinition tool = tableModel.rowAt(modelRow);
        if (tool == null) {
            detailPanel.clear();
            return;
        }
        detailPanel.show(tool);
    }

    enum HeaderState {
        NONE, PARTIAL, ALL
    }

    private final class HeaderClickListener extends MouseAdapter {
        @Override
        public void mouseClicked(MouseEvent event) {
            JTableHeader header = table.getTableHeader();
            int viewColumn = header.columnAtPoint(event.getPoint());
            if (viewColumn < 0) {
                return;
            }
            int modelColumn = table.convertColumnIndexToModel(viewColumn);
            if (modelColumn != SelectableInventoryTableModel.SELECT_COLUMN_INDEX) {
                return;
            }
            toggleAllSelections();
        }
    }

    private static final class TriStateHeaderRenderer implements TableCellRenderer {
        private HeaderState state = HeaderState.NONE;

        void setState(HeaderState state) {
            this.state = state;
        }

        @Override
        public Component getTableCellRendererComponent(JTable table, Object value,
                                                       boolean isSelected, boolean hasFocus,
                                                       int row, int column) {
            JTableHeader header = table.getTableHeader();
            java.awt.Color background = header != null ? header.getBackground() : table.getBackground();
            java.awt.Color foreground = header != null ? header.getForeground() : table.getForeground();
            return new TriStateHeaderComponent(background, foreground, state);
        }
    }

    private static final class TriStateHeaderComponent extends JPanel {
        private final HeaderState state;

        TriStateHeaderComponent(java.awt.Color background, java.awt.Color foreground, HeaderState state) {
            super(new BorderLayout());
            this.state = state;
            setOpaque(true);
            setBackground(background);
            setForeground(foreground);
            setBorder(BorderFactory.createMatteBorder(0, 0, 1, 1, separatorColor()));
            JCheckBox box = new JCheckBox();
            box.setHorizontalAlignment(SwingConstants.CENTER);
            box.setOpaque(false);
            box.setSelected(state == HeaderState.ALL);
            box.setEnabled(true);
            add(box, BorderLayout.CENTER);
            setToolTipText(tooltipFor(state));
        }

        @Override
        protected void paintComponent(Graphics g) {
            super.paintComponent(g);
            if (state != HeaderState.PARTIAL) {
                return;
            }
            Graphics2D g2 = (Graphics2D) g.create();
            try {
                g2.setRenderingHint(RenderingHints.KEY_ANTIALIASING, RenderingHints.VALUE_ANTIALIAS_ON);
                g2.setColor(getForeground());
                int width = getWidth();
                int height = getHeight();
                int dashWidth = Math.max(8, width / 4);
                int x = (width - dashWidth) / 2;
                int y = height / 2 - 1;
                g2.fillRect(x, y, dashWidth, 2);
            } finally {
                g2.dispose();
            }
        }

        private static String tooltipFor(HeaderState state) {
            return switch (state) {
                case ALL -> "All tools selected — click to clear";
                case NONE -> "No tools selected — click to select all";
                case PARTIAL -> "Some tools selected — click to select all";
            };
        }

        private static java.awt.Color separatorColor() {
            java.awt.Color color = UIManager.getColor("TableHeader.bottomSeparatorColor");
            if (color != null) {
                return color;
            }
            java.awt.Color fallback = UIManager.getColor("Separator.foreground");
            return fallback != null ? fallback : java.awt.Color.GRAY;
        }
    }

    private final class SelectCellRenderer implements TableCellRenderer {
        private final JCheckBox checkBox = new JCheckBox();

        SelectCellRenderer() {
            checkBox.setHorizontalAlignment(SwingConstants.CENTER);
            checkBox.setOpaque(true);
        }

        @Override
        public Component getTableCellRendererComponent(JTable table, Object value,
                                                       boolean isSelected, boolean hasFocus,
                                                       int row, int column) {
            checkBox.setSelected(Boolean.TRUE.equals(value));
            checkBox.setBackground(isSelected
                    ? table.getSelectionBackground() : table.getBackground());
            checkBox.setForeground(isSelected
                    ? table.getSelectionForeground() : table.getForeground());
            int modelRow = table.convertRowIndexToModel(row);
            McpToolDefinition tool = tableModel.rowAt(modelRow);
            checkBox.setToolTipText(tool != null
                    ? ToolTableModel.annotationTooltip(tool.annotations()) : null);
            return checkBox;
        }
    }

    private static final class AnnotationsCellRenderer extends DefaultTableCellRenderer {

        private static final Color DESTRUCTIVE_DARK = new Color(0xEF5350);
        private static final Color DESTRUCTIVE_LIGHT = new Color(0xC0392B);

        AnnotationsCellRenderer() {
        }

        @Override
        public Component getTableCellRendererComponent(JTable table, Object value,
                                                       boolean isSelected, boolean hasFocus,
                                                       int row, int column) {
            JLabel label = (JLabel) super.getTableCellRendererComponent(
                    table, value, isSelected, hasFocus, row, column);
            ToolAnnotations annotations = annotationsFor(table, row);
            label.setToolTipText(annotations != null
                    ? ToolTableModel.annotationTooltip(annotations) : null);
            if (!isSelected) {
                label.setForeground(foregroundFor(value, table.getBackground(), table.getForeground()));
            }
            return label;
        }

        private static Color foregroundFor(Object value, Color background, Color defaultForeground) {
            if (!ToolTableModel.LABEL_DESTRUCTIVE.equals(value)) {
                return defaultForeground;
            }
            return ThemeColors.isDark(background) ? DESTRUCTIVE_DARK : DESTRUCTIVE_LIGHT;
        }

        private static ToolAnnotations annotationsFor(JTable table, int viewRow) {
            if (!(table.getModel() instanceof ToolTableModel model)) {
                return null;
            }
            int modelRow = table.convertRowIndexToModel(viewRow);
            McpToolDefinition tool = model.rowAt(modelRow);
            return tool != null ? tool.annotations() : null;
        }
    }

    static final class ToolDetailPanel extends JPanel {

        private static final String CARD_EMPTY = "empty";
        private static final String CARD_DETAIL = "detail";
        private static final String PLACEHOLDER_TEXT = "Select a tool to view its details.";

        private final CardLayout cardLayout = new CardLayout();
        private final JLabel nameLabel = SwingHtmlGuard.disableHtml(new JLabel());
        private final JTextArea descriptionArea = buildDescriptionArea();
        private final RawEditor parametersEditor;

        ToolDetailPanel(UserInterface userInterface) {
            super();
            this.parametersEditor = userInterface.createRawEditor(EditorOptions.READ_ONLY);
            setLayout(cardLayout);
            add(buildPlaceholderCard(), CARD_EMPTY);
            add(buildDetailCard(), CARD_DETAIL);
            cardLayout.show(this, CARD_EMPTY);
        }

        void show(McpToolDefinition tool) {
            nameLabel.setText(tool.name());
            descriptionArea.setText(safeText(tool.description()));
            descriptionArea.setCaretPosition(0);
            parametersEditor.setContents(ByteArray.byteArray(prettyPrint(tool.inputSchema())));
            cardLayout.show(this, CARD_DETAIL);
        }

        void clear() {
            cardLayout.show(this, CARD_EMPTY);
        }

        JLabel nameLabelForTest() {
            return nameLabel;
        }

        JTextArea descriptionAreaForTest() {
            return descriptionArea;
        }

        RawEditor parametersEditorForTest() {
            return parametersEditor;
        }

        private JPanel buildPlaceholderCard() {
            JPanel card = new JPanel(new BorderLayout());
            JLabel placeholder = new JLabel(PLACEHOLDER_TEXT, SwingConstants.CENTER);
            placeholder.setEnabled(false);
            card.add(placeholder, BorderLayout.CENTER);
            return card;
        }

        private JComponent buildDetailCard() {
            nameLabel.setFont(nameLabel.getFont().deriveFont(
                    Font.BOLD, nameLabel.getFont().getSize() + 2f));
            nameLabel.setBorder(BorderFactory.createEmptyBorder(6, 6, 6, 6));

            JTabbedPane tabs = new JTabbedPane();
            tabs.addTab("Description", new JScrollPane(descriptionArea));
            tabs.addTab("Parameters", parametersEditor.uiComponent());

            JPanel card = new JPanel(new BorderLayout());
            card.add(nameLabel, BorderLayout.NORTH);
            card.add(tabs, BorderLayout.CENTER);
            return card;
        }

        private static JTextArea buildDescriptionArea() {
            JTextArea area = new JTextArea();
            area.setEditable(false);
            area.setLineWrap(true);
            area.setWrapStyleWord(true);
            return area;
        }

        private static String safeText(String value) {
            return value != null ? value : "";
        }

        private static String prettyPrint(String json) {
            if (json == null || json.isBlank()) {
                return "";
            }
            try {
                JsonNode node = McpObjectMapper.INSTANCE.readTree(json);
                return McpObjectMapper.INSTANCE.writerWithDefaultPrettyPrinter().writeValueAsString(node);
            } catch (Exception ex) {
                return json;
            }
        }
    }
}
