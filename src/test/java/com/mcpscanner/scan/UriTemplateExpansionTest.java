package com.mcpscanner.scan;

import com.mcpscanner.scan.UriTemplateExpansion.Result;
import com.mcpscanner.scan.UriTemplateExpansion.Variable;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

class UriTemplateExpansionTest {

    @Test
    void expandsSinglePlaceholderWithVariableName() {
        Result result = UriTemplateExpansion.expand("file:///{path}");

        assertThat(result.expandedUri()).isEqualTo("file:///path");
        assertThat(result.variables()).hasSize(1);
        assertThat(result.variables().get(0).name()).isEqualTo("path");
    }

    @Test
    void singleVariableByteRangeCoversSubstitutedName() {
        Result result = UriTemplateExpansion.expand("file:///{path}");

        Variable variable = result.variables().get(0);
        assertThat(slice(result.expandedUri(), variable)).isEqualTo("path");
    }

    @Test
    void expandsMultiplePlaceholdersInOrder() {
        Result result = UriTemplateExpansion.expand("db://{server}/{database}/{table}");

        assertThat(result.expandedUri()).isEqualTo("db://server/database/table");
        assertThat(result.variables()).extracting(Variable::name)
                .containsExactly("server", "database", "table");
    }

    @Test
    void multipleVariableByteRangesCoverEachSubstitutedName() {
        Result result = UriTemplateExpansion.expand("db://{server}/{database}/{table}");

        List<Variable> variables = result.variables();
        assertThat(slice(result.expandedUri(), variables.get(0))).isEqualTo("server");
        assertThat(slice(result.expandedUri(), variables.get(1))).isEqualTo("database");
        assertThat(slice(result.expandedUri(), variables.get(2))).isEqualTo("table");
    }

    @Test
    void templateWithoutPlaceholdersExpandsUnchanged() {
        Result result = UriTemplateExpansion.expand("file:///static/path");

        assertThat(result.expandedUri()).isEqualTo("file:///static/path");
        assertThat(result.variables()).isEmpty();
    }

    @Test
    void emptyTemplateReturnsEmptyResult() {
        Result result = UriTemplateExpansion.expand("");

        assertThat(result.expandedUri()).isEmpty();
        assertThat(result.variables()).isEmpty();
    }

    @Test
    void nullTemplateReturnsEmptyResult() {
        Result result = UriTemplateExpansion.expand(null);

        assertThat(result.expandedUri()).isEmpty();
        assertThat(result.variables()).isEmpty();
    }

    @Test
    void unterminatedPlaceholderIsTreatedAsLiteral() {
        Result result = UriTemplateExpansion.expand("file:///{unterminated");

        assertThat(result.expandedUri()).isEqualTo("file:///{unterminated");
        assertThat(result.variables()).isEmpty();
    }

    @Test
    void adjacentPlaceholdersExpandWithoutSeparator() {
        Result result = UriTemplateExpansion.expand("{a}{b}");

        assertThat(result.expandedUri()).isEqualTo("ab");
        assertThat(result.variables()).extracting(Variable::name).containsExactly("a", "b");
        assertThat(slice(result.expandedUri(), result.variables().get(0))).isEqualTo("a");
        assertThat(slice(result.expandedUri(), result.variables().get(1))).isEqualTo("b");
    }

    @Test
    void repeatedVariableProducesTwoIndependentRanges() {
        Result result = UriTemplateExpansion.expand("{x}/{x}");

        assertThat(result.expandedUri()).isEqualTo("x/x");
        assertThat(result.variables()).hasSize(2);

        Variable first = result.variables().get(0);
        Variable second = result.variables().get(1);
        assertThat(slice(result.expandedUri(), first)).isEqualTo("x");
        assertThat(slice(result.expandedUri(), second)).isEqualTo("x");
        assertThat(first.startInclusive()).isNotEqualTo(second.startInclusive());
    }

    @Test
    void byteRangesAccountForMultibyteCharactersInLiteralSegments() {
        Result result = UriTemplateExpansion.expand("héllo/{name}");

        assertThat(result.expandedUri()).isEqualTo("héllo/name");
        Variable variable = result.variables().get(0);
        assertThat(slice(result.expandedUri(), variable)).isEqualTo("name");
    }

    private static String slice(String expanded, Variable variable) {
        byte[] bytes = expanded.getBytes(StandardCharsets.UTF_8);
        return new String(
                Arrays.copyOfRange(bytes, variable.startInclusive(), variable.endExclusive()),
                StandardCharsets.UTF_8);
    }
}
