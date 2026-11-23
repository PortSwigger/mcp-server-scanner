package com.mcpscanner.ui.access;

import com.mcpscanner.access.AccessFixtures;
import com.mcpscanner.access.AccessMatrix;
import com.mcpscanner.access.AccessRow;
import com.mcpscanner.checks.api.AccessOutcome;
import com.mcpscanner.checks.api.Principal;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Map;
import java.util.Set;

import static com.mcpscanner.access.AccessFixtures.ALICE;
import static com.mcpscanner.access.AccessFixtures.readOnlyTool;
import static com.mcpscanner.access.AccessFixtures.toolKey;
import static org.assertj.core.api.Assertions.assertThat;

class SyntheticColumnsTest {

    private static final Principal FAKE_TOKEN = Principal.fakeToken(Map::of);

    @Test
    void noCredentialAndFakeTokenColumnsSitBeforeTheExpectation() {
        AccessTableModel model = new AccessTableModel((key, expectation) -> { });

        model.show(List.of(ALICE), List.of(), Set.of());

        assertThat(model.getColumnName(2)).isEqualTo("No credential");
        assertThat(model.getColumnName(3)).isEqualTo("Fake token");
        assertThat(model.getColumnName(4)).isEqualTo("Who should reach it");
    }

    @Test
    void theFakeTokenCellShowsItsListingAndCallOutcome() {
        AccessRow row = fakeTokenListsAndReaches();

        assertThat(AccessCellRenderer.text(row, new AccessColumn.FakeToken()))
                .isEqualTo(AccessCellText.ANOMALY + "● listed · ✓ same result");
        assertThat(AccessCellRenderer.text(row, new AccessColumn.Anonymous())).isEqualTo("○ hidden · ✗ refused");
    }

    @Test
    void theFakeTokenDetailSaysAnInvalidTokenWasUsed() {
        AccessRow row = fakeTokenListsAndReaches();

        assertThat(AccessDetailText.describe(row, new AccessColumn.FakeToken()))
                .contains("search — Fake token (an invalid token the server never issued)")
                .contains("Listed in Fake token's own tools/list.")
                .contains("With the fake token the call returned the same result as Primary.");
    }

    private static AccessRow fakeTokenListsAndReaches() {
        AccessMatrix matrix = new AccessFixtures()
                .lists(ALICE, List.of(readOnlyTool("search")), List.of())
                .lists(Principal.anonymous(), List.of(), List.of())
                .lists(FAKE_TOKEN, List.of(readOnlyTool("search")), List.of())
                .matrix();
        matrix.recordAnonymous(toolKey("search"), AccessOutcome.REFUSED);
        matrix.record(toolKey("search"), Principal.FAKE_TOKEN_ID, AccessOutcome.SAME_RESULT);
        return matrix.snapshot().rows().get(0);
    }
}
