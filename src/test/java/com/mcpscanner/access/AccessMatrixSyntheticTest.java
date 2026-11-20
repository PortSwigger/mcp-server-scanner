package com.mcpscanner.access;

import com.mcpscanner.checks.api.AccessOutcome;
import com.mcpscanner.checks.api.Principal;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Map;

import static com.mcpscanner.access.AccessFixtures.ALICE;
import static com.mcpscanner.access.AccessFixtures.BOB;
import static com.mcpscanner.access.AccessFixtures.tool;
import static com.mcpscanner.access.AccessFixtures.toolKey;
import static org.assertj.core.api.Assertions.assertThat;

class AccessMatrixSyntheticTest {

    private static final Principal NO_CREDENTIAL = Principal.anonymous();
    private static final Principal FAKE_TOKEN = Principal.fakeToken(Map::of);

    @Test
    void aToolOnlyTheFakeTokenListsGetsARowOwnedByThePrimary() {
        AccessMatrix matrix = new AccessFixtures().compare(BOB)
                .lists(ALICE, List.of(tool("search")), List.of())
                .lists(BOB, List.of(tool("search")), List.of())
                .lists(FAKE_TOKEN, List.of(tool("search"), tool("list_users")), List.of())
                .matrix();

        AccessRow row = matrix.row(toolKey("list_users")).orElseThrow();

        assertThat(matrix.snapshot().rows()).extracting(each -> each.item().key().name())
                .containsExactly("search", "list_users");
        assertThat(row.owner()).isEqualTo(ALICE);
        assertThat(row.cell(ALICE.id()).listing()).isEqualTo(ListingState.HIDDEN);
        assertThat(row.cell(BOB.id()).listing()).isEqualTo(ListingState.HIDDEN);
        assertThat(row.synthetic(Principal.FAKE_TOKEN_ID).listing()).isEqualTo(ListingState.LISTED);
        assertThat(row.item().tool()).isPresent();
    }

    @Test
    void theMatrixShowsOnlyTheSyntheticPrincipalsItIsGiven() {
        AccessMatrix matrix = new AccessFixtures().compare(BOB)
                .lists(ALICE, List.of(tool("search")), List.of())
                .lists(FAKE_TOKEN, List.of(tool("search"), tool("list_users")), List.of())
                .matrix(List.of(NO_CREDENTIAL));

        assertThat(matrix.snapshot().rows()).extracting(each -> each.item().key().name()).containsExactly("search");
        assertThat(matrix.row(toolKey("list_users"))).isEmpty();
    }

    @Test
    void syntheticCellsShowListedAndHiddenFromTheirOwnListings() {
        AccessRow row = singleRow(new AccessFixtures()
                .lists(ALICE, List.of(tool("search")), List.of())
                .lists(NO_CREDENTIAL, List.of(), List.of())
                .lists(FAKE_TOKEN, List.of(tool("search")), List.of()));

        assertThat(row.anonymous().listing()).isEqualTo(ListingState.HIDDEN);
        assertThat(row.synthetic(Principal.FAKE_TOKEN_ID).listing()).isEqualTo(ListingState.LISTED);
    }

    @Test
    void syntheticCellsWithoutAListingShowNoListing() {
        AccessRow row = singleRow(new AccessFixtures().lists(ALICE, List.of(tool("search")), List.of()));

        assertThat(row.anonymous().listing()).isEqualTo(ListingState.NO_LISTING);
        assertThat(row.synthetic(Principal.FAKE_TOKEN_ID).listing()).isEqualTo(ListingState.NO_LISTING);
    }

    @Test
    void theFakeTokenCellShowsItsOwnCallOutcome() {
        AccessMatrix matrix = new AccessFixtures().lists(ALICE, List.of(tool("search")), List.of()).matrix();

        matrix.record(toolKey("search"), Principal.FAKE_TOKEN_ID, AccessOutcome.SAME_RESULT);

        AccessRow row = matrix.snapshot().rows().get(0);
        assertThat(row.synthetic(Principal.FAKE_TOKEN_ID).outcome()).contains(AccessOutcome.SAME_RESULT);
        assertThat(row.synthetic(Principal.FAKE_TOKEN_ID).anomaly()).isTrue();
        assertThat(row.cells()).doesNotContainKey(Principal.FAKE_TOKEN_ID);
    }

    private static AccessRow singleRow(AccessFixtures fixtures) {
        List<AccessRow> rows = fixtures.matrix().snapshot().rows();
        assertThat(rows).hasSize(1);
        return rows.get(0);
    }
}
