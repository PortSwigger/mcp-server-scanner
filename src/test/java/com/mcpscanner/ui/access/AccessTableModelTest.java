package com.mcpscanner.ui.access;

import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Set;

import static com.mcpscanner.access.AccessFixtures.ALICE;
import static com.mcpscanner.access.AccessFixtures.BOB;
import static org.assertj.core.api.Assertions.assertThat;

class AccessTableModelTest {

    private final AccessTableModel model = new AccessTableModel((key, expectation) -> { });

    @Test
    void marksTheColumnOfAUserCollectingFoundNoIdsFor() {
        model.show(List.of(ALICE, BOB), List.of(), Set.of(BOB.id()));

        assertThat(model.getColumnName(2)).isEqualTo(PrincipalLabels.column(BOB) + " ⚠");
        assertThat(model.columnAt(2).note()).contains(AccessColumn.Identity.WITHOUT_IDS_NOTE);
        assertThat(model.getColumnName(1)).isEqualTo(PrincipalLabels.column(ALICE));
        assertThat(model.columnAt(1).note()).isEmpty();
    }

    @Test
    void clearingTheMarkChangesTheHeader() {
        model.show(List.of(ALICE, BOB), List.of(), Set.of(BOB.id()));
        model.show(List.of(ALICE, BOB), List.of(), Set.of());

        assertThat(model.getColumnName(2)).isEqualTo(PrincipalLabels.column(BOB));
    }
}
