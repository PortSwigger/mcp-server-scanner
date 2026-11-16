package com.mcpscanner.checks.catalog.sqlinjection;

import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

class ValueSlotsTest {

    @Test
    void aPlainValueHasOnlyTheWholeValueSlot() {
        assertThat(ValueSlots.of("notes")).containsExactly(ValueSlot.whole("notes"));
    }

    @Test
    void aUriAlsoOffersItsAuthorityAndPathSegments() {
        assertThat(ValueSlots.of("mysql://users/data?limit=5")).extracting(ValueSlot::segment)
                .containsExactly("mysql://users/data?limit=5", "users", "data");
    }

    @Test
    void aSegmentRewriteKeepsTheRestOfTheUri() {
        ValueSlot host = ValueSlots.of("mysql://users/data").get(1);

        assertThat(host.with("`users`")).isEqualTo("mysql://`users`/data");
        assertThat(host.isWhole()).isFalse();
    }

    @Test
    void offersAtMostFourSegments() {
        assertThat(ValueSlots.of("x://a/b/c/d/e/f")).hasSize(5);
    }
}
