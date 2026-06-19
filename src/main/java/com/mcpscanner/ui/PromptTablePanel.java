package com.mcpscanner.ui;

import com.mcpscanner.mcp.McpPromptDefinition;
import com.mcpscanner.mcp.PromptArgument;
import com.mcpscanner.ui.widgets.SwingHtmlGuard;

import javax.swing.BorderFactory;
import javax.swing.JComponent;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JSplitPane;
import javax.swing.JTable;
import javax.swing.JTextArea;
import javax.swing.SwingConstants;
import javax.swing.table.AbstractTableModel;
import java.awt.BorderLayout;
import java.awt.CardLayout;
import java.awt.Dimension;
import java.awt.Font;
import java.util.ArrayList;
import java.util.List;

public class PromptTablePanel extends AbstractInventoryTablePanel<McpPromptDefinition> {

    @Override
    protected InventoryTableModel<McpPromptDefinition> createTableModel() {
        return new PromptTableModel();
    }

    @Override
    protected InventoryDetailPanel<McpPromptDefinition> createDetailPanel() {
        return new PromptDetailPanel();
    }

    public List<McpPromptDefinition> selectedPrompts() {
        return ((PromptTableModel) getTableModel()).selectedItems();
    }

    @Override
    PromptDetailPanel getDetailPanelForTest() {
        return (PromptDetailPanel) super.getDetailPanelForTest();
    }

    static final class PromptDetailPanel extends JPanel implements InventoryDetailPanel<McpPromptDefinition> {

        private static final String CARD_EMPTY = "empty";
        private static final String CARD_DETAIL = "detail";
        private static final String PLACEHOLDER_TEXT = "Select a prompt to view its details.";

        private final CardLayout cardLayout = new CardLayout();
        private final JLabel nameLabel = SwingHtmlGuard.disableHtml(buildNameLabel());
        private final JTextArea descriptionArea = buildDescriptionArea();
        private final PromptArgumentsTableModel argumentsModel = new PromptArgumentsTableModel();
        private final JTable argumentsTable = new JTable(argumentsModel);

        PromptDetailPanel() {
            super();
            SwingHtmlGuard.guardStringColumns(argumentsTable);
            setLayout(cardLayout);
            add(buildPlaceholderCard(), CARD_EMPTY);
            add(buildDetailCard(), CARD_DETAIL);
            cardLayout.show(this, CARD_EMPTY);
        }

        @Override
        public JComponent component() {
            return this;
        }

        @Override
        public void show(McpPromptDefinition prompt) {
            nameLabel.setText(safeText(prompt.name()));
            descriptionArea.setText(safeText(prompt.description()));
            descriptionArea.setCaretPosition(0);
            argumentsModel.populate(prompt.arguments());
            cardLayout.show(this, CARD_DETAIL);
        }

        @Override
        public void clear() {
            cardLayout.show(this, CARD_EMPTY);
        }

        JLabel nameLabelForTest() {
            return nameLabel;
        }

        JTextArea descriptionAreaForTest() {
            return descriptionArea;
        }

        PromptArgumentsTableModel argumentsModelForTest() {
            return argumentsModel;
        }

        JTable argumentsTableForTest() {
            return argumentsTable;
        }

        private JPanel buildPlaceholderCard() {
            JPanel card = new JPanel(new BorderLayout());
            JLabel placeholder = new JLabel(PLACEHOLDER_TEXT, SwingConstants.CENTER);
            placeholder.setEnabled(false);
            card.add(placeholder, BorderLayout.CENTER);
            return card;
        }

        private JPanel buildDetailCard() {
            JSplitPane splitPane = new JSplitPane(JSplitPane.VERTICAL_SPLIT, buildDescriptionPane(), buildArgumentsPane());
            splitPane.setResizeWeight(0.5);
            splitPane.setContinuousLayout(true);
            splitPane.setOneTouchExpandable(true);
            splitPane.setBorder(null);

            JPanel card = new JPanel(new BorderLayout());
            card.setBorder(BorderFactory.createEmptyBorder(8, 8, 8, 8));
            card.add(splitPane, BorderLayout.CENTER);
            return card;
        }

        private JPanel buildDescriptionPane() {
            JScrollPane descriptionScrollPane = new JScrollPane(descriptionArea);
            descriptionScrollPane.setPreferredSize(new Dimension(0, 150));

            JPanel pane = new JPanel(new BorderLayout(0, 8));
            pane.add(nameLabel, BorderLayout.NORTH);
            pane.add(descriptionScrollPane, BorderLayout.CENTER);
            return pane;
        }

        private JPanel buildArgumentsPane() {
            JLabel argumentsHeader = new JLabel("Arguments");
            argumentsHeader.setFont(argumentsHeader.getFont().deriveFont(Font.BOLD));

            JScrollPane argumentsScrollPane = new JScrollPane(argumentsTable);
            argumentsScrollPane.setPreferredSize(new Dimension(0, 150));

            JPanel pane = new JPanel(new BorderLayout(0, 8));
            pane.add(argumentsHeader, BorderLayout.NORTH);
            pane.add(argumentsScrollPane, BorderLayout.CENTER);
            return pane;
        }

        private static JLabel buildNameLabel() {
            JLabel label = new JLabel();
            label.setFont(label.getFont().deriveFont(Font.BOLD, label.getFont().getSize() + 2f));
            return label;
        }

        private static JTextArea buildDescriptionArea() {
            JTextArea area = new JTextArea();
            area.setEditable(false);
            area.setLineWrap(true);
            area.setWrapStyleWord(true);
            return area;
        }
    }

    static final class PromptArgumentsTableModel extends AbstractTableModel {

        private static final String[] COLUMN_NAMES = {"Name", "Description", "Required"};
        private final List<PromptArgument> rows = new ArrayList<>();

        @Override
        public int getRowCount() {
            return rows.size();
        }

        @Override
        public int getColumnCount() {
            return COLUMN_NAMES.length;
        }

        @Override
        public String getColumnName(int column) {
            return COLUMN_NAMES[column];
        }

        @Override
        public Class<?> getColumnClass(int column) {
            return column == 2 ? Boolean.class : String.class;
        }

        @Override
        public boolean isCellEditable(int row, int column) {
            return false;
        }

        @Override
        public Object getValueAt(int row, int column) {
            PromptArgument argument = rows.get(row);
            return switch (column) {
                case 0 -> argument.name();
                case 1 -> argument.description();
                case 2 -> argument.required();
                default -> null;
            };
        }

        void populate(List<PromptArgument> newArguments) {
            rows.clear();
            rows.addAll(newArguments);
            fireTableDataChanged();
        }
    }
}
