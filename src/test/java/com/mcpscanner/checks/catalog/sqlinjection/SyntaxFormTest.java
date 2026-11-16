package com.mcpscanner.checks.catalog.sqlinjection;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;

import java.util.stream.Collectors;

import static org.assertj.core.api.Assertions.assertThat;

class SyntaxFormTest {

    @ParameterizedTest
    @EnumSource(SyntaxForm.class)
    void theFalsifierHasTheSameCharactersAsTheEquivalent(SyntaxForm form) {
        String equivalent = form.equivalent("notes", "qabc");
        String falsifier = form.falsifier("notes", "qabc");

        assertThat(falsifier).isNotEqualTo(equivalent).hasSameSizeAs(equivalent);
        assertThat(sorted(falsifier)).isEqualTo(sorted(equivalent));
    }

    @ParameterizedTest
    @EnumSource(SyntaxForm.class)
    void theFalsifierStartsLikeTheEquivalentAfterTheValue(SyntaxForm form) {
        String equivalent = form.equivalent("notes", "qabc");
        String falsifier = form.falsifier("notes", "qabc");

        assertThat(falsifier.charAt(0)).isEqualTo(equivalent.charAt(0));
    }

    @Test
    void quotesOnlyIdentifierShapedValuesAsIdentifiers() {
        assertThat(SyntaxForm.applicableTo(ValueSlot.whole("users"))).contains(SyntaxForm.BACKTICK_IDENTIFIER);
        assertThat(SyntaxForm.applicableTo(ValueSlot.whole("two words")))
                .doesNotContain(SyntaxForm.BACKTICK_IDENTIFIER, SyntaxForm.DOUBLE_QUOTED_IDENTIFIER);
    }

    @Test
    void neverRewritesAUriSegmentWithAUriDelimiter() {
        ValueSlot host = ValueSlots.of("mysql://users/data").get(1);

        assertThat(SyntaxForm.applicableTo(host)).doesNotContain(SyntaxForm.INLINE_COMMENT)
                .contains(SyntaxForm.BACKTICK_IDENTIFIER);
    }

    private static String sorted(String text) {
        return text.chars().sorted().mapToObj(Character::toString).collect(Collectors.joining());
    }
}
