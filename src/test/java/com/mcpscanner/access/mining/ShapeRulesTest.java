package com.mcpscanner.access.mining;

import com.fasterxml.jackson.databind.node.BooleanNode;
import com.fasterxml.jackson.databind.node.IntNode;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.junit.jupiter.api.Test;


import static org.assertj.core.api.Assertions.assertThat;

class ShapeRulesTest {

    @ParameterizedTest
    @ValueSource(strings = {"c0a11ce0-0000-4000-8000-000000055544", "42", "spring-sale", "INV_2026.01"})
    void idShapedValues(String value) {
        assertThat(IdShape.idShaped(value)).isTrue();
    }

    @ParameterizedTest
    @ValueSource(strings = {"https://a.test/x", "/etc/passwd", "a/b", "..", "C:\\x", "~root", "two words", ""})
    void routeShapedOrProseValuesAreNotIds(String value) {
        assertThat(IdShape.idShaped(value)).isFalse();
    }

    @Test
    void integersAreIdsButBooleansAndNegativesAreNot() {
        assertThat(IdShape.idShaped(IntNode.valueOf(7))).isTrue();
        assertThat(IdShape.idShaped(IntNode.valueOf(-7))).isFalse();
        assertThat(IdShape.idShaped(BooleanNode.TRUE)).isFalse();
    }

    @Test
    void anIdLeafUnderAnObjectAliasesThatObjectsIdArgument() {
        assertThat(Aliases.ofLeaf("id", "campaigns")).contains("id", "campaignid", "campaign");
        assertThat(Aliases.ofLeaf("campaign_id", null)).contains("campaignid");
        assertThat(Aliases.ofArgument("campaignId", "stats")).containsExactly("campaignid");
        assertThat(Aliases.ofArgument("id", "campaigns_get")).contains("id", "campaignid");
    }
}
