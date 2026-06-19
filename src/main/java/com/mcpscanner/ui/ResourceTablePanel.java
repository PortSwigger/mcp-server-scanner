package com.mcpscanner.ui;

import com.mcpscanner.mcp.McpResourceDefinition;
import com.mcpscanner.ui.widgets.SwingHtmlGuard;

import java.util.List;
import javax.swing.BorderFactory;
import javax.swing.Box;
import javax.swing.JComponent;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JTextArea;
import javax.swing.SwingConstants;
import java.awt.BorderLayout;
import java.awt.CardLayout;
import java.awt.Component;
import java.awt.Font;

public class ResourceTablePanel extends AbstractInventoryTablePanel<McpResourceDefinition> {

    @Override
    protected InventoryTableModel<McpResourceDefinition> createTableModel() {
        return new ResourceTableModel();
    }

    @Override
    protected InventoryDetailPanel<McpResourceDefinition> createDetailPanel() {
        return new ResourceDetailPanel();
    }

    public List<McpResourceDefinition> selectedResources() {
        return ((ResourceTableModel) getTableModel()).selectedItems();
    }

    @Override
    ResourceDetailPanel getDetailPanelForTest() {
        return (ResourceDetailPanel) super.getDetailPanelForTest();
    }

    static final class ResourceDetailPanel extends JPanel implements InventoryDetailPanel<McpResourceDefinition> {

        private static final String CARD_EMPTY = "empty";
        private static final String CARD_DETAIL = "detail";
        private static final String PLACEHOLDER_TEXT = "Select a resource to view its details.";

        private final CardLayout cardLayout = new CardLayout();
        private final JLabel uriLabel = SwingHtmlGuard.disableHtml(buildUriLabel());
        private final JLabel nameLabel = SwingHtmlGuard.disableHtml(buildNameLabel());
        private final JLabel mimeTypeLabel = SwingHtmlGuard.disableHtml(new JLabel());
        private final JTextArea descriptionArea = buildDescriptionArea();

        ResourceDetailPanel() {
            super();
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
        public void show(McpResourceDefinition resource) {
            uriLabel.setText(safeText(resource.uri()));
            nameLabel.setText(safeText(resource.name()));
            mimeTypeLabel.setText(safeText(resource.mimeType()));
            descriptionArea.setText(safeText(resource.description()));
            descriptionArea.setCaretPosition(0);
            cardLayout.show(this, CARD_DETAIL);
        }

        @Override
        public void clear() {
            cardLayout.show(this, CARD_EMPTY);
        }

        JLabel uriLabelForTest() {
            return uriLabel;
        }

        JLabel nameLabelForTest() {
            return nameLabel;
        }

        JLabel mimeTypeLabelForTest() {
            return mimeTypeLabel;
        }

        JTextArea descriptionAreaForTest() {
            return descriptionArea;
        }

        private JPanel buildPlaceholderCard() {
            JPanel card = new JPanel(new BorderLayout());
            JLabel placeholder = new JLabel(PLACEHOLDER_TEXT, SwingConstants.CENTER);
            placeholder.setEnabled(false);
            card.add(placeholder, BorderLayout.CENTER);
            return card;
        }

        private JPanel buildDetailCard() {
            Box stack = Box.createVerticalBox();
            stack.setBorder(BorderFactory.createEmptyBorder(8, 8, 8, 8));
            stack.add(leftAligned(uriLabel));
            stack.add(Box.createVerticalStrut(4));
            stack.add(leftAligned(nameLabel));
            stack.add(Box.createVerticalStrut(4));
            stack.add(leftAligned(mimeTypeLabel));
            stack.add(Box.createVerticalStrut(8));
            stack.add(new JScrollPane(descriptionArea));

            JPanel card = new JPanel(new BorderLayout());
            card.add(stack, BorderLayout.CENTER);
            return card;
        }

        private static Component leftAligned(JLabel label) {
            label.setAlignmentX(Component.LEFT_ALIGNMENT);
            return label;
        }

        private static JLabel buildUriLabel() {
            JLabel label = new JLabel();
            label.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 12));
            return label;
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
}
