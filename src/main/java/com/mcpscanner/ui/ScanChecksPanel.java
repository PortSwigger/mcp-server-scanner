package com.mcpscanner.ui;

import burp.api.montoya.scanner.audit.issues.AuditIssueSeverity;
import com.mcpscanner.checks.registry.ManagedCheck;
import com.mcpscanner.checks.registry.ScanCheckRegistry;
import com.mcpscanner.checks.registry.ScanCheckSettings;
import com.mcpscanner.ui.widgets.HyperlinkLabel;
import com.mcpscanner.ui.widgets.ThemeColors;

import javax.swing.BorderFactory;
import javax.swing.Box;
import javax.swing.BoxLayout;
import javax.swing.JComponent;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JTable;
import javax.swing.JTextArea;
import javax.swing.ListSelectionModel;
import javax.swing.RowSorter.SortKey;
import javax.swing.SortOrder;
import javax.swing.SwingUtilities;
import javax.swing.UIManager;
import javax.swing.border.EmptyBorder;
import javax.swing.event.ListSelectionListener;
import javax.swing.table.DefaultTableCellRenderer;
import javax.swing.table.TableRowSorter;
import java.awt.BorderLayout;
import java.awt.Color;
import java.awt.Component;
import java.awt.Font;
import java.awt.event.MouseEvent;
import java.net.URI;
import java.net.URISyntaxException;
import java.util.Comparator;
import java.util.List;

public final class ScanChecksPanel extends JPanel {

    private static final int ENABLED_COLUMN_WIDTH = 70;
    private static final int NAME_COLUMN_WIDTH = 320;
    private static final int SEVERITY_COLUMN_WIDTH = 100;
    private static final int SCOPE_COLUMN_WIDTH = 120;
    private static final int ROW_HEIGHT = 24;
    private static final int LINK_VERTICAL_GAP = 2;
    // Gap before the "Sources:" header, centralised so spacing stays uniform regardless of description text.
    private static final int SOURCES_TOP_GAP = 10;

    private final ScanChecksTableModel model;
    private final JTable table;
    private final JTextArea descriptionArea;
    private final JPanel referencesPanel;
    private final java.util.function.Consumer<Throwable> linkErrorSink;

    public ScanChecksPanel(ScanCheckRegistry registry, ScanCheckSettings settings) {
        this(registry, settings, throwable -> {});
    }

    public ScanChecksPanel(ScanCheckRegistry registry, ScanCheckSettings settings,
                           java.util.function.Consumer<Throwable> linkErrorSink) {
        super(new BorderLayout());
        this.linkErrorSink = linkErrorSink;
        this.model = new ScanChecksTableModel(registry.all(), settings);
        this.table = buildTable(model);
        this.descriptionArea = buildDescriptionArea();
        this.referencesPanel = buildReferencesPanel();

        add(buildInstructionLabel(), BorderLayout.NORTH);
        add(new JScrollPane(table), BorderLayout.CENTER);
        add(buildDescriptionPanel(), BorderLayout.SOUTH);

        table.getSelectionModel().addListSelectionListener(onSelectionChanged());
        settings.addListener((id, enabled) -> SwingUtilities.invokeLater(() -> refreshRowFor(id)));

        if (model.getRowCount() > 0) {
            table.getSelectionModel().setSelectionInterval(0, 0);
        }
    }

    JTable tableForTest() {
        return table;
    }

    ScanChecksTableModel modelForTest() {
        return model;
    }

    private static JLabel buildInstructionLabel() {
        JLabel label = new JLabel(
                "Toggle individual scan checks. Disabled checks are skipped during audits.");
        label.setBorder(new EmptyBorder(8, 8, 4, 8));
        return label;
    }

    private static JTable buildTable(ScanChecksTableModel model) {
        JTable table = new JTable(model) {
            @Override
            public String getToolTipText(MouseEvent event) {
                int viewRow = rowAtPoint(event.getPoint());
                if (viewRow < 0) {
                    return null;
                }
                int modelRow = convertRowIndexToModel(viewRow);
                ManagedCheck check = model.checkAt(modelRow);
                if (check == null) {
                    return null;
                }
                String description = check.descriptor().description();
                return description.isBlank() ? null : description;
            }
        };
        table.setShowGrid(false);
        table.setAutoResizeMode(JTable.AUTO_RESIZE_SUBSEQUENT_COLUMNS);
        table.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
        table.setRowHeight(ROW_HEIGHT);
        table.setDefaultRenderer(AuditIssueSeverity.class, new SeverityRenderer());
        installRowSorter(table, model);

        table.getColumnModel().getColumn(ScanChecksTableModel.COLUMN_ENABLED)
                .setPreferredWidth(ENABLED_COLUMN_WIDTH);
        table.getColumnModel().getColumn(ScanChecksTableModel.COLUMN_ENABLED)
                .setMaxWidth(ENABLED_COLUMN_WIDTH);
        table.getColumnModel().getColumn(ScanChecksTableModel.COLUMN_NAME)
                .setPreferredWidth(NAME_COLUMN_WIDTH);
        table.getColumnModel().getColumn(ScanChecksTableModel.COLUMN_SEVERITY)
                .setPreferredWidth(SEVERITY_COLUMN_WIDTH);
        table.getColumnModel().getColumn(ScanChecksTableModel.COLUMN_SCOPE)
                .setPreferredWidth(SCOPE_COLUMN_WIDTH);
        return table;
    }

    private static void installRowSorter(JTable table, ScanChecksTableModel model) {
        TableRowSorter<ScanChecksTableModel> sorter = new TableRowSorter<>(model);
        sorter.setComparator(ScanChecksTableModel.COLUMN_SEVERITY, bySeverityRank());
        sorter.setSortKeys(List.of(new SortKey(
                ScanChecksTableModel.COLUMN_SEVERITY, SortOrder.DESCENDING)));
        table.setRowSorter(sorter);
    }

    private static Comparator<AuditIssueSeverity> bySeverityRank() {
        return Comparator.comparingInt(ScanChecksPanel::severityRank);
    }

    private static int severityRank(AuditIssueSeverity severity) {
        return switch (severity) {
            case HIGH -> 4;
            case MEDIUM -> 3;
            case LOW -> 2;
            case INFORMATION -> 1;
            case FALSE_POSITIVE -> 0;
        };
    }

    private static JTextArea buildDescriptionArea() {
        JTextArea area = new JTextArea();
        area.setEditable(false);
        area.setOpaque(false);
        area.setLineWrap(true);
        area.setWrapStyleWord(true);
        area.setRows(4);
        area.setBorder(new EmptyBorder(8, 8, 4, 8));
        return area;
    }

    private static JPanel buildReferencesPanel() {
        JPanel panel = new JPanel();
        panel.setLayout(new BoxLayout(panel, BoxLayout.Y_AXIS));
        panel.setOpaque(false);
        panel.setBorder(new EmptyBorder(0, 8, 8, 8));
        panel.setVisible(false);
        return panel;
    }

    private JComponent buildDescriptionPanel() {
        JPanel panel = new JPanel(new BorderLayout());
        panel.setBorder(BorderFactory.createCompoundBorder(
                new EmptyBorder(4, 8, 8, 8),
                BorderFactory.createTitledBorder("Description")));
        panel.add(descriptionArea, BorderLayout.NORTH);
        panel.add(referencesPanel, BorderLayout.CENTER);
        return panel;
    }

    private ListSelectionListener onSelectionChanged() {
        return event -> {
            if (event.getValueIsAdjusting()) {
                return;
            }
            updateDescription();
        };
    }

    private void updateDescription() {
        int viewRow = table.getSelectedRow();
        if (viewRow < 0) {
            descriptionArea.setText("");
            renderReferences(List.of());
            return;
        }
        int modelRow = table.convertRowIndexToModel(viewRow);
        ManagedCheck check = model.checkAt(modelRow);
        descriptionArea.setText(check != null ? check.descriptor().description().stripTrailing() : "");
        descriptionArea.setCaretPosition(0);
        renderReferences(check != null ? check.descriptor().references() : List.of());
    }

    private void renderReferences(List<String> references) {
        referencesPanel.removeAll();
        if (references.isEmpty()) {
            referencesPanel.setVisible(false);
            referencesPanel.revalidate();
            referencesPanel.repaint();
            return;
        }
        referencesPanel.add(Box.createVerticalStrut(SOURCES_TOP_GAP));
        referencesPanel.add(buildSourcesHeader());
        referencesPanel.add(Box.createVerticalStrut(LINK_VERTICAL_GAP));
        for (int i = 0; i < references.size(); i++) {
            referencesPanel.add(buildReferenceLabel(references.get(i)));
            if (i < references.size() - 1) {
                referencesPanel.add(Box.createVerticalStrut(LINK_VERTICAL_GAP));
            }
        }
        referencesPanel.setVisible(true);
        referencesPanel.revalidate();
        referencesPanel.repaint();
    }

    private static JLabel buildSourcesHeader() {
        JLabel label = new JLabel("Sources:");
        label.setFont(label.getFont().deriveFont(Font.BOLD));
        label.setAlignmentX(Component.LEFT_ALIGNMENT);
        return label;
    }

    private JComponent buildReferenceLabel(String url) {
        URI uri = parseUriOrNull(url);
        if (uri == null) {
            JLabel fallback = new JLabel(url);
            fallback.setAlignmentX(Component.LEFT_ALIGNMENT);
            return fallback;
        }
        HyperlinkLabel link = new HyperlinkLabel(url, uri, linkErrorSink);
        link.setAlignmentX(Component.LEFT_ALIGNMENT);
        return link;
    }

    private static URI parseUriOrNull(String url) {
        try {
            return new URI(url);
        } catch (URISyntaxException ignored) {
            return null;
        }
    }

    private void refreshRowFor(String id) {
        int row = model.rowForId(id);
        if (row >= 0) {
            model.fireTableRowsUpdated(row, row);
        }
    }

    private static final class SeverityRenderer extends DefaultTableCellRenderer {

        private static final Color HIGH_DARK = new Color(0xEF5350);
        private static final Color HIGH_LIGHT = new Color(0xC62828);
        private static final Color MEDIUM_DARK = new Color(0xFFD54F);
        private static final Color MEDIUM_LIGHT = new Color(0xF57C00);
        private static final Color LOW_DARK = new Color(0x66BB6A);
        private static final Color LOW_LIGHT = new Color(0x2E7D32);

        @Override
        public Component getTableCellRendererComponent(JTable table, Object value,
                                                       boolean isSelected, boolean hasFocus,
                                                       int row, int column) {
            Component component = super.getTableCellRendererComponent(
                    table, format(value), isSelected, hasFocus, row, column);
            if (!isSelected) {
                component.setForeground(foregroundFor(value, ThemeColors.isDark(table.getBackground())));
            }
            return component;
        }

        private static String format(Object value) {
            if (!(value instanceof AuditIssueSeverity severity)) {
                return value != null ? value.toString() : "";
            }
            return switch (severity) {
                case HIGH -> "High";
                case MEDIUM -> "Medium";
                case LOW -> "Low";
                case INFORMATION -> "Info";
                case FALSE_POSITIVE -> "False positive";
            };
        }

        private static Color foregroundFor(Object value, boolean dark) {
            if (!(value instanceof AuditIssueSeverity severity)) {
                return defaultForeground();
            }
            return switch (severity) {
                case HIGH -> dark ? HIGH_DARK : HIGH_LIGHT;
                case MEDIUM -> dark ? MEDIUM_DARK : MEDIUM_LIGHT;
                case LOW -> dark ? LOW_DARK : LOW_LIGHT;
                case INFORMATION, FALSE_POSITIVE -> defaultForeground();
            };
        }

        private static Color defaultForeground() {
            Color color = UIManager.getColor("Label.foreground");
            return color != null ? color : Color.DARK_GRAY;
        }
    }
}
