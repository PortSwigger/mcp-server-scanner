package com.mcpscanner.ui.detail.schema;

import com.mcpscanner.testutil.SwingTree;
import com.mcpscanner.ui.detail.RawJsonView;
import org.junit.jupiter.api.Test;

import javax.swing.JComponent;
import javax.swing.JLabel;
import javax.swing.text.JTextComponent;
import java.awt.Component;
import java.util.List;

import static com.mcpscanner.ui.detail.schema.SchemaFixtures.json;
import static org.assertj.core.api.Assertions.assertThat;

class SchemaTableTest {

    private static final int NARROW_PANE = 420;

    private final SchemaTable table = new SchemaTable("Arguments object");

    @Test
    void petersSchemaShowsHeadingSummaryDialectAndRow() {
        table.show(json(SchemaFixtures.PETERS_SCHEMA), "2025-06-18");

        assertThat(texts()).contains("Arguments object",
                "1 parameter · 1 required · no extra properties rule",
                "JSON Schema draft-07", "Parameter", "Type", "Constraints", "Description",
                "id", "required", "string", "format: uuid", "pattern", SchemaFixtures.UUID_PATTERN, "None given");
        assertThat(table.parameterCount()).isEqualTo(1);
        assertThat(table.isEmpty()).isFalse();
    }

    @Test
    void headingHasTheSameTopPaddingAsTheRawTabHeading() {
        table.show(json(SchemaFixtures.PETERS_SCHEMA), null);

        Component header = SwingTree.descendants(table).stream().filter(SchemaHeader.class::isInstance).findFirst().orElseThrow();

        assertThat(((JComponent) header).getInsets().top).isEqualTo(RawJsonView.PADDING);
    }

    @Test
    void longPatternWrapsInsteadOfWideningThePanel() {
        table.show(json(SchemaFixtures.PETERS_SCHEMA), null);

        JTextComponent pattern = textComponent(SchemaFixtures.UUID_PATTERN);
        assertThat(pattern).isInstanceOfSatisfying(javax.swing.JTextArea.class, area -> {
            assertThat(area.getLineWrap()).isTrue();
            assertThat(area.getWrapStyleWord()).isFalse();
        });
        table.setSize(NARROW_PANE, 4000);
        SwingTree.layOut(table);
        assertThat(pattern.getWidth()).isPositive().isLessThan(NARROW_PANE);
        assertThat(pattern.getPreferredSize().width).isLessThan(NARROW_PANE / 4);
    }

    @Test
    void rowsStayAtTheTopWhenThePaneIsTallerThanTheTable() {
        table.show(json(SchemaFixtures.PETERS_SCHEMA), null);
        table.setSize(1000, 2000);
        SwingTree.layOut(table);

        Component grid = SwingTree.descendants(table).stream().filter(SchemaGrid.class::isInstance).findFirst().orElseThrow();
        int gridTop = javax.swing.SwingUtilities.convertPoint(grid.getParent(), grid.getLocation(), table).y;

        assertThat(grid.getHeight()).isEqualTo(grid.getPreferredSize().height);
        assertThat(gridTop).isLessThan(table.getHeight() / 4);
    }

    @Test
    void nestedRowsCarryTreeMarkersAndOtherKeywordsBox() {
        table.show(json(SchemaFixtures.NESTED_SCHEMA), "2025-11-25");

        assertThat(texts()).contains("JSON Schema 2020-12 (default)", "▾", "└", "└ ▾", "array of string",
                "string | null", "from", "$defs/DateRange", "one of", "open", "closed", "all", "default",
                "\"open\"", "Other schema keywords", "x-internal: true   ·   filters.deprecated: true");
    }

    @Test
    void otherKeywordsBoxIsAbsentWhenThereAreNone() {
        table.show(json(SchemaFixtures.PETERS_SCHEMA), null);

        assertThat(texts()).doesNotContain("Other schema keywords");
    }

    @Test
    void headingIsCallerSettable() {
        SchemaTable output = new SchemaTable("Output object");
        output.show(json(SchemaFixtures.NESTED_SCHEMA), null);

        assertThat(texts(output)).contains("Output object").doesNotContain("Arguments object");
    }

    @Test
    void emptySchemaReportsEmpty() {
        table.show(json("{\"type\":\"object\"}"), "2024-11-05");

        assertThat(table.isEmpty()).isTrue();
        assertThat(table.parameterCount()).isZero();
        assertThat(texts()).contains("JSON Schema unspecified");
    }

    @Test
    void showReplacesPreviousContent() {
        table.show(json(SchemaFixtures.NESTED_SCHEMA), null);
        table.show(json(SchemaFixtures.PETERS_SCHEMA), null);

        assertThat(texts()).doesNotContain("query", "Other schema keywords");
    }

    @Test
    void serverTextIsNeverInterpretedAsHtml() {
        String markup = "<html><img src='http://attacker.test/x'></html>";
        table.show(json("{\"properties\":{\"" + markup.replace("'", "\\u0027") + "\":{\"description\":\""
                + markup.replace("'", "\\u0027") + "\",\"format\":\"" + markup.replace("'", "\\u0027")
                + "\"}},\"$schema\":\"" + markup.replace("'", "\\u0027") + "\"}"), null);

        assertThat(texts()).contains(markup, "format: " + markup, "JSON Schema " + markup);
        assertThat(descendants()).filteredOn(c -> c instanceof JLabel || c instanceof JTextComponent)
                .allSatisfy(c -> assertThat(((JComponent) c).getClientProperty("html.disable"))
                        .isEqualTo(Boolean.TRUE));
    }

    private List<String> texts() {
        return texts(table);
    }

    private static List<String> texts(SchemaTable root) {
        return SwingTree.descendants(root).stream()
                .map(SchemaTableTest::textOf)
                .filter(text -> text != null)
                .map(String::strip)
                .toList();
    }

    private static String textOf(Component component) {
        if (component instanceof JLabel label) {
            return label.getText();
        }
        if (component instanceof JTextComponent text) {
            return text.getText();
        }
        return null;
    }

    private JTextComponent textComponent(String text) {
        return descendants().stream()
                .filter(JTextComponent.class::isInstance).map(JTextComponent.class::cast)
                .filter(component -> text.equals(component.getText()))
                .findFirst().orElseThrow();
    }

    private List<Component> descendants() {
        return SwingTree.descendants(table);
    }
}
