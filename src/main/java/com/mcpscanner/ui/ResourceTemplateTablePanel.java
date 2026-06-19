package com.mcpscanner.ui;

import com.mcpscanner.mcp.McpResourceTemplateDefinition;
import com.mcpscanner.ui.widgets.SwingHtmlGuard;

import java.util.List;
import javax.swing.BorderFactory;
import javax.swing.JComponent;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JTextArea;
import javax.swing.SwingConstants;
import java.awt.BorderLayout;
import java.awt.CardLayout;
import java.awt.Dimension;
import java.awt.Font;
import java.awt.GridLayout;

public class ResourceTemplateTablePanel extends AbstractInventoryTablePanel<McpResourceTemplateDefinition> {

    @Override
    protected InventoryTableModel<McpResourceTemplateDefinition> createTableModel() {
        return new ResourceTemplateTableModel();
    }

    @Override
    protected InventoryDetailPanel<McpResourceTemplateDefinition> createDetailPanel() {
        return new ResourceTemplateDetailPanel();
    }

    public List<McpResourceTemplateDefinition> selectedResourceTemplates() {
        return ((ResourceTemplateTableModel) getTableModel()).selectedItems();
    }

    @Override
    ResourceTemplateDetailPanel getDetailPanelForTest() {
        return (ResourceTemplateDetailPanel) super.getDetailPanelForTest();
    }

    static final class ResourceTemplateDetailPanel extends JPanel implements InventoryDetailPanel<McpResourceTemplateDefinition> {

        private static final String CARD_EMPTY = "empty";
        private static final String CARD_DETAIL = "detail";
        private static final String PLACEHOLDER_TEXT = "Select a template to view its details.";

        private final CardLayout cardLayout = new CardLayout();
        private final JLabel uriTemplateLabel = SwingHtmlGuard.disableHtml(buildUriTemplateLabel());
        private final JLabel nameLabel = SwingHtmlGuard.disableHtml(buildNameLabel());
        private final JLabel mimeTypeLabel = SwingHtmlGuard.disableHtml(new JLabel());
        private final JTextArea descriptionArea = buildDescriptionArea();

        ResourceTemplateDetailPanel() {
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
        public void show(McpResourceTemplateDefinition template) {
            uriTemplateLabel.setText(safeText(template.uriTemplate()));
            nameLabel.setText(safeText(template.name()));
            mimeTypeLabel.setText(safeText(template.mimeType()));
            descriptionArea.setText(safeText(template.description()));
            descriptionArea.setCaretPosition(0);
            cardLayout.show(this, CARD_DETAIL);
        }

        @Override
        public void clear() {
            cardLayout.show(this, CARD_EMPTY);
        }

        JLabel uriTemplateLabelForTest() {
            return uriTemplateLabel;
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
            JScrollPane descriptionScrollPane = new JScrollPane(descriptionArea);
            descriptionScrollPane.setPreferredSize(new Dimension(0, 150));

            JPanel card = new JPanel(new BorderLayout(0, 8));
            card.setBorder(BorderFactory.createEmptyBorder(8, 8, 8, 8));
            card.add(buildHeaderCluster(), BorderLayout.NORTH);
            card.add(descriptionScrollPane, BorderLayout.CENTER);
            return card;
        }

        private JPanel buildHeaderCluster() {
            JPanel headerCluster = new JPanel(new GridLayout(0, 1, 0, 4));
            headerCluster.add(uriTemplateLabel);
            headerCluster.add(nameLabel);
            headerCluster.add(mimeTypeLabel);
            return headerCluster;
        }

        private static JLabel buildUriTemplateLabel() {
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
