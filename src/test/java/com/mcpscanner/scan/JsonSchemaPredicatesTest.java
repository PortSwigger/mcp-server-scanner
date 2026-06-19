package com.mcpscanner.scan;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.mcpscanner.mcp.McpObjectMapper;
import com.mcpscanner.testutil.MontoyaTestFactory;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import static org.assertj.core.api.Assertions.assertThat;

class JsonSchemaPredicatesTest {

    @BeforeAll
    static void installFactory() {
        MontoyaTestFactory.install();
    }

    @ParameterizedTest
    @ValueSource(strings = {
            "{\"type\":\"string\"}",
            "{\"type\":[\"string\",\"null\"]}",
            "{\"type\":[\"null\",\"string\"]}",
            "{\"anyOf\":[{\"type\":\"string\"},{\"type\":\"null\"}]}",
            "{\"anyOf\":[{\"type\":\"string\"}]}",
            "{\"oneOf\":[{\"type\":\"string\"},{\"type\":\"integer\"}]}",
            "{\"type\":\"string\",\"format\":\"uri\"}"
    })
    void recognisesStringShapes(String schemaJson) throws JsonProcessingException {
        JsonNode schema = readTree(schemaJson);

        assertThat(JsonSchemaPredicates.isStringSchema(schema)).isTrue();
    }

    @ParameterizedTest
    @ValueSource(strings = {
            "{\"type\":\"integer\"}",
            "{\"type\":\"array\",\"items\":{\"type\":\"string\"}}",
            "{\"type\":\"object\"}",
            "{}",
            "{\"anyOf\":[{\"type\":\"integer\"},{\"type\":\"null\"}]}"
    })
    void rejectsNonStringShapes(String schemaJson) throws JsonProcessingException {
        JsonNode schema = readTree(schemaJson);

        assertThat(JsonSchemaPredicates.isStringSchema(schema)).isFalse();
    }

    @Test
    void rejectsNullNodeDefensively() {
        assertThat(JsonSchemaPredicates.isStringSchema(null)).isFalse();
    }

    @Test
    void rejectsExplicitJacksonNullNode() {
        JsonNode nullNode = McpObjectMapper.INSTANCE.nullNode();

        assertThat(JsonSchemaPredicates.isStringSchema(nullNode)).isFalse();
    }

    @Test
    void resolvesSingleLevelRefToStringDefinition() throws JsonProcessingException {
        String rootJson = "{\"type\":\"object\","
                + "\"properties\":{\"path\":{\"$ref\":\"#/definitions/Path\"}},"
                + "\"definitions\":{\"Path\":{\"type\":\"string\"}}}";
        JsonNode root = readTree(rootJson);
        JsonNode property = root.path("properties").path("path");

        assertThat(JsonSchemaPredicates.isStringSchema(property, root)).isTrue();
    }

    @Test
    void doesNotResolveRefWhenRootMissing() throws JsonProcessingException {
        JsonNode schema = readTree("{\"$ref\":\"#/definitions/Path\"}");

        // Without a root, $ref cannot be resolved — predicate must say false,
        // never throw.
        assertThat(JsonSchemaPredicates.isStringSchema(schema)).isFalse();
    }

    @Test
    void doesNotResolveRefToNonStringDefinition() throws JsonProcessingException {
        String rootJson = "{\"type\":\"object\","
                + "\"properties\":{\"count\":{\"$ref\":\"#/definitions/Count\"}},"
                + "\"definitions\":{\"Count\":{\"type\":\"integer\"}}}";
        JsonNode root = readTree(rootJson);
        JsonNode property = root.path("properties").path("count");

        assertThat(JsonSchemaPredicates.isStringSchema(property, root)).isFalse();
    }

    @Test
    void resolvesFiniteNestedRefChainToString() throws JsonProcessingException {
        // With the visited-set defence, a finite ref chain that terminates at
        // a string definition resolves correctly. A -> B -> {type: string}
        // is safe because each pointer is visited at most once.
        String rootJson = "{\"properties\":{\"x\":{\"$ref\":\"#/definitions/A\"}},"
                + "\"definitions\":{\"A\":{\"$ref\":\"#/definitions/B\"},"
                + "\"B\":{\"type\":\"string\"}}}";
        JsonNode root = readTree(rootJson);
        JsonNode property = root.path("properties").path("x");

        assertThat(JsonSchemaPredicates.isStringSchema(property, root)).isTrue();
    }

    @Test
    void rejectsSelfReferentialRef() throws JsonProcessingException {
        // A $ref pointing at itself must not infinite-loop
        // the predicate. The visited-set-free design relies on rejecting
        // ref-to-ref outright, which covers self-refs as a special case.
        String rootJson = "{\"properties\":{\"x\":{\"$ref\":\"#/definitions/Loop\"}},"
                + "\"definitions\":{\"Loop\":{\"$ref\":\"#/definitions/Loop\"}}}";
        JsonNode root = readTree(rootJson);
        JsonNode property = root.path("properties").path("x");

        assertThat(JsonSchemaPredicates.isStringSchema(property, root)).isFalse();
    }

    @Test
    @Timeout(5)
    void rejectsRefThroughAnyOfCycle() throws JsonProcessingException {
        // x -> A -> anyOf[A] -> ... : composition-through-ref cycle. The
        // direct ref-to-ref guard does not catch this because A resolves to an
        // object whose top-level field is anyOf, not $ref.
        String rootJson = "{\"properties\":{\"x\":{\"$ref\":\"#/definitions/A\"}},"
                + "\"definitions\":{\"A\":{\"anyOf\":[{\"$ref\":\"#/definitions/A\"}]}}}";
        JsonNode root = readTree(rootJson);
        JsonNode property = root.path("properties").path("x");

        assertThat(JsonSchemaPredicates.isStringSchema(property, root)).isFalse();
    }

    @Test
    @Timeout(5)
    void rejectsRefThroughOneOfCycle() throws JsonProcessingException {
        String rootJson = "{\"properties\":{\"x\":{\"$ref\":\"#/definitions/A\"}},"
                + "\"definitions\":{\"A\":{\"oneOf\":[{\"$ref\":\"#/definitions/A\"}]}}}";
        JsonNode root = readTree(rootJson);
        JsonNode property = root.path("properties").path("x");

        assertThat(JsonSchemaPredicates.isStringSchema(property, root)).isFalse();
    }

    @Test
    @Timeout(5)
    void rejectsLongerCompositionCycle() throws JsonProcessingException {
        // A -> anyOf[B] -> anyOf[C] -> anyOf[A]
        String rootJson = "{\"properties\":{\"x\":{\"$ref\":\"#/definitions/A\"}},"
                + "\"definitions\":{"
                + "\"A\":{\"anyOf\":[{\"$ref\":\"#/definitions/B\"}]},"
                + "\"B\":{\"anyOf\":[{\"$ref\":\"#/definitions/C\"}]},"
                + "\"C\":{\"anyOf\":[{\"$ref\":\"#/definitions/A\"}]}}}";
        JsonNode root = readTree(rootJson);
        JsonNode property = root.path("properties").path("x");

        assertThat(JsonSchemaPredicates.isStringSchema(property, root)).isFalse();
    }

    @Test
    @Timeout(5)
    void rejectsSelfReferentialAnyOf() throws JsonProcessingException {
        // A is {anyOf: [{$ref: #/definitions/A}, {type: integer}]} — the
        // self-loop via anyOf must short-circuit, and integer is not string,
        // so the predicate must answer false.
        String rootJson = "{\"properties\":{\"x\":{\"$ref\":\"#/definitions/A\"}},"
                + "\"definitions\":{\"A\":{\"anyOf\":["
                + "{\"$ref\":\"#/definitions/A\"},"
                + "{\"type\":\"integer\"}]}}}";
        JsonNode root = readTree(rootJson);
        JsonNode property = root.path("properties").path("x");

        assertThat(JsonSchemaPredicates.isStringSchema(property, root)).isFalse();
    }

    @Test
    void recognisesStringThroughDeepNonCyclicComposition() throws JsonProcessingException {
        // A -> anyOf[B] -> anyOf[{type: string}] — three levels deep, no
        // cycle. Confirms the visited-set defence does not regress legitimate
        // composition chains.
        String rootJson = "{\"properties\":{\"x\":{\"$ref\":\"#/definitions/A\"}},"
                + "\"definitions\":{"
                + "\"A\":{\"anyOf\":[{\"$ref\":\"#/definitions/B\"}]},"
                + "\"B\":{\"anyOf\":[{\"type\":\"string\"}]}}}";
        JsonNode root = readTree(rootJson);
        JsonNode property = root.path("properties").path("x");

        assertThat(JsonSchemaPredicates.isStringSchema(property, root)).isTrue();
    }

    @Test
    void resolvesRefInsideAnyOfBranch() throws JsonProcessingException {
        String rootJson = "{\"type\":\"object\","
                + "\"properties\":{\"path\":{\"anyOf\":["
                + "{\"$ref\":\"#/definitions/Path\"},"
                + "{\"type\":\"null\"}]}},"
                + "\"definitions\":{\"Path\":{\"type\":\"string\"}}}";
        JsonNode root = readTree(rootJson);
        JsonNode property = root.path("properties").path("path");

        assertThat(JsonSchemaPredicates.isStringSchema(property, root)).isTrue();
    }

    private static JsonNode readTree(String json) throws JsonProcessingException {
        return McpObjectMapper.INSTANCE.readTree(json);
    }
}
