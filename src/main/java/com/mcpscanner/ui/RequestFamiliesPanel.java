package com.mcpscanner.ui;

import com.mcpscanner.scan.ScanGenerationSettings;
import com.mcpscanner.scan.request.RequestFamily;
import com.mcpscanner.scan.request.RequestFamilyGroup;
import com.mcpscanner.ui.widgets.OptionRow;
import com.mcpscanner.ui.widgets.ResponsiveColumns;
import com.mcpscanner.ui.widgets.ScrollableForm;
import com.mcpscanner.ui.widgets.ToggleGroupCard;
import com.mcpscanner.ui.widgets.ToggleOption;
import com.mcpscanner.ui.widgets.UiStyle;
import com.mcpscanner.ui.widgets.WrappingText;

import javax.swing.BorderFactory;
import javax.swing.Box;
import javax.swing.BoxLayout;
import javax.swing.JButton;
import javax.swing.JComponent;
import javax.swing.JLabel;
import javax.swing.JPanel;
import java.awt.BorderLayout;
import java.awt.FlowLayout;
import java.util.Arrays;
import java.util.List;

public final class RequestFamiliesPanel extends JPanel {

    static final String REQUESTS_TITLE = "Requests sent by Scan";
    static final String REQUESTS_DESCRIPTION = "Scan this request always sends the request you chose.";
    static final String INSERTION_POINTS_TITLE = "Insertion points";
    static final String HEADER_FIELDS_LABEL = "Offer MCP headers as insertion points";
    static final String HEADER_FIELDS_HINT = "Mcp-Method, Mcp-Name, MCP-Protocol-Version, Mcp-Session-Id";
    static final String META_ENVELOPE_LABEL = "Fuzz request metadata (_meta) on every request";
    static final String META_ENVELOPE_HINT = "Off: _meta is fuzzed once per server, on one request of each scan.";
    static final String SELECT_ALL = "Select all";
    static final String SELECT_NONE = "Select none";

    private static final int MIN_COLUMN_WIDTH = 260;
    private static final int MAX_COLUMNS = 2;
    private static final int GAP = 10;
    private static final int SECTION_GAP = 16;
    private static final int BUTTON_GAP = 6;

    private final ScanGenerationSettings settings;
    private final List<ToggleGroupCard> cards;

    public RequestFamiliesPanel(ScanGenerationSettings settings) {
        super(new BorderLayout());
        this.settings = settings;
        this.cards = Arrays.stream(RequestFamilyGroup.values()).map(this::card).toList();
        add(ScrollableForm.wrap(topAligned(content())), BorderLayout.CENTER);
    }

    private JPanel content() {
        JPanel content = new JPanel();
        content.setLayout(new BoxLayout(content, BoxLayout.Y_AXIS));
        content.setBorder(BorderFactory.createEmptyBorder(8, 8, 8, 8));
        content.add(heading(REQUESTS_TITLE, REQUESTS_DESCRIPTION, selectionButtons()));
        content.add(Box.createVerticalStrut(GAP));
        content.add(familyColumns());
        content.add(Box.createVerticalStrut(SECTION_GAP));
        content.add(heading(INSERTION_POINTS_TITLE));
        content.add(Box.createVerticalStrut(4));
        content.add(new OptionRow(headerFieldsOption()));
        content.add(new OptionRow(metaEnvelopeOption()));
        return content;
    }

    private ToggleGroupCard card(RequestFamilyGroup group) {
        List<ToggleOption> options = Arrays.stream(RequestFamily.values())
                .filter(family -> family.group() == group)
                .map(this::option)
                .toList();
        return new ToggleGroupCard(group.title(), group.description(), options);
    }

    private ToggleOption option(RequestFamily family) {
        return new ToggleOption(family.label(), family.hint(), settings.isEnabled(family),
                enabled -> settings.setEnabled(family, enabled));
    }

    private ToggleOption headerFieldsOption() {
        return new ToggleOption(HEADER_FIELDS_LABEL, HEADER_FIELDS_HINT, settings.headerFieldsEnabled(),
                settings::setHeaderFieldsEnabled);
    }

    private ToggleOption metaEnvelopeOption() {
        return new ToggleOption(META_ENVELOPE_LABEL, META_ENVELOPE_HINT, settings.metaEnvelopeFuzzedOnEveryRequest(),
                settings::setMetaEnvelopeFuzzedOnEveryRequest);
    }

    private ResponsiveColumns familyColumns() {
        ResponsiveColumns columns = new ResponsiveColumns(MIN_COLUMN_WIDTH, MAX_COLUMNS, GAP);
        cards.forEach(columns::add);
        return columns;
    }

    private JPanel selectionButtons() {
        JPanel buttons = new JPanel(new FlowLayout(FlowLayout.RIGHT, BUTTON_GAP, 0));
        buttons.setOpaque(false);
        buttons.add(selectionButton(SELECT_ALL, true));
        buttons.add(selectionButton(SELECT_NONE, false));
        return buttons;
    }

    private JButton selectionButton(String text, boolean selected) {
        JButton button = new JButton(text);
        button.addActionListener(event -> cards.forEach(card -> card.selectAll(selected)));
        return button;
    }

    private static JPanel heading(String title) {
        JPanel heading = new JPanel(new BorderLayout(8, 2));
        heading.setOpaque(false);
        heading.add(UiStyle.styleClass(new JLabel(title), UiStyle.HEADING), BorderLayout.WEST);
        return heading;
    }

    private static JPanel heading(String title, String description, JComponent trailing) {
        JPanel heading = heading(title);
        heading.add(trailing, BorderLayout.EAST);
        heading.add(new WrappingText(description).muted(), BorderLayout.SOUTH);
        return heading;
    }

    private static JPanel topAligned(JComponent content) {
        JPanel wrapper = new JPanel(new BorderLayout());
        wrapper.add(content, BorderLayout.NORTH);
        return wrapper;
    }
}
