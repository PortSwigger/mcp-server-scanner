package com.mcpscanner.ui.access;

import com.mcpscanner.checks.api.AccessExpectation;
import org.junit.jupiter.api.Test;

import javax.swing.JList;
import javax.swing.JLabel;

import static org.assertj.core.api.Assertions.assertThat;

class ExpectationTextTest {

    @Test
    void labelsSayWhoMayCallItWithTheOwnersName() {
        assertThat(ExpectationText.label(AccessExpectation.SHARED_BY_DESIGN, "admin"))
                .isEqualTo("Anyone — same result for everyone");
        assertThat(ExpectationText.label(AccessExpectation.ANY_SIGNED_IN, "admin"))
                .isEqualTo("Anyone — but only their own data");
        assertThat(ExpectationText.label(AccessExpectation.NOT_LOWER, "admin")).isEqualTo("admin's level or above");
        assertThat(ExpectationText.label(AccessExpectation.HIGHER_ONLY, "admin"))
                .isEqualTo("Only users above admin's level");
        assertThat(ExpectationText.label(AccessExpectation.OWNER_ONLY, "admin")).isEqualTo("Only admin");
    }

    @Test
    void aMissingOwnerNameFallsBackToTheOwner() {
        assertThat(ExpectationText.label(AccessExpectation.NOT_LOWER, " ")).isEqualTo("The owner's level or above");
        assertThat(ExpectationText.label(AccessExpectation.OWNER_ONLY, "")).isEqualTo("Only the owner");
        assertThat(ExpectationText.tooltip(AccessExpectation.OWNER_ONLY, "")).startsWith("Every user other than the owner");
    }

    @Test
    void tooltipsSayWhoIsFlagged() {
        assertThat(ExpectationText.tooltip(AccessExpectation.SHARED_BY_DESIGN, "admin")).startsWith("Nobody is flagged");
        assertThat(ExpectationText.tooltip(AccessExpectation.ANY_SIGNED_IN, "admin"))
                .contains("only if they get admin's data back").contains("get_my_profile");
        assertThat(ExpectationText.tooltip(AccessExpectation.NOT_LOWER, "admin")).startsWith("Lower-privilege users");
        assertThat(ExpectationText.tooltip(AccessExpectation.HIGHER_ONLY, "admin")).contains("same-level");
        assertThat(ExpectationText.tooltip(AccessExpectation.OWNER_ONLY, "admin"))
                .contains("other than admin").contains("delete_user, run_sql");
    }

    @Test
    void choiceRendererShowsTheOwnerLiterallyAndEscapesItsTooltip() {
        ExpectationChoiceRenderer renderer = new ExpectationChoiceRenderer();
        renderer.showOwner("<html><b>x</b>");

        JLabel label = (JLabel) renderer.getListCellRendererComponent(new JList<>(), AccessExpectation.OWNER_ONLY, 0,
                false, false);

        assertThat(label.getText()).isEqualTo("Only <html><b>x</b>");
        assertThat(label.getToolTipText()).doesNotContain("<").contains("&lt;html&gt;");
    }

    @Test
    void matrixCellsRenderOwnerNamesLiterally() {
        AccessCellRenderer renderer = new AccessCellRenderer(new AccessTableModel((key, expectation) -> { }));

        assertThat(renderer.getClientProperty("html.disable")).isEqualTo(Boolean.TRUE);
    }
}
