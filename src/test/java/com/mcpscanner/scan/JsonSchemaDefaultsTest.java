package com.mcpscanner.scan;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.mcpscanner.testutil.MontoyaTestFactory;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

class JsonSchemaDefaultsTest {

    private static final ObjectMapper MAPPER = new ObjectMapper();

    @BeforeAll
    static void installFactory() {
        MontoyaTestFactory.install();
    }

    @Test
    void stringPropertyDefaultsToTest() {
        String schema = """
                {"properties":{"name":{"type":"string"}}}""";

        String result = JsonSchemaDefaults.buildDefaultArgumentsJson(schema);

        assertThat(result).isEqualTo("{\"name\":\"test\"}");
    }

    @Test
    void integerPropertyProducesNativeIntegerOne() throws Exception {
        String schema = """
                {"properties":{"count":{"type":"integer"}}}""";

        String result = JsonSchemaDefaults.buildDefaultArgumentsJson(schema);

        JsonNode node = MAPPER.readTree(result).get("count");
        assertThat(node.isIntegralNumber()).isTrue();
        assertThat(node.asLong()).isEqualTo(1L);
    }

    @Test
    void numberPropertyProducesNativeFloatingPointValue() throws Exception {
        String schema = """
                {"properties":{"ratio":{"type":"number"}}}""";

        String result = JsonSchemaDefaults.buildDefaultArgumentsJson(schema);

        JsonNode node = MAPPER.readTree(result).get("ratio");
        assertThat(node.isNumber()).isTrue();
        assertThat(node.isTextual()).isFalse();
    }

    @Test
    void booleanPropertyDefaultsToFalseLeastSideEffect() throws Exception {
        String schema = """
                {"properties":{"enabled":{"type":"boolean"}}}""";

        String result = JsonSchemaDefaults.buildDefaultArgumentsJson(schema);

        JsonNode node = MAPPER.readTree(result).get("enabled");
        assertThat(node.isBoolean()).isTrue();
        assertThat(node.asBoolean()).isFalse();
    }

    @Test
    void arrayPropertyDefaultsToEmptyArray() {
        String schema = """
                {"properties":{"items":{"type":"array"}}}""";

        String result = JsonSchemaDefaults.buildDefaultArgumentsJson(schema);

        assertThat(result).isEqualTo("{\"items\":[]}");
    }

    @Test
    void objectPropertyDefaultsToEmptyObject() {
        String schema = """
                {"properties":{"config":{"type":"object"}}}""";

        String result = JsonSchemaDefaults.buildDefaultArgumentsJson(schema);

        assertThat(result).isEqualTo("{\"config\":{}}");
    }

    @Test
    void multiplePropertiesProducesNativeTypedDefaults() throws Exception {
        String schema = """
                {"properties":{"name":{"type":"string"},"count":{"type":"integer"},"enabled":{"type":"boolean"}}}""";

        String result = JsonSchemaDefaults.buildDefaultArgumentsJson(schema);

        JsonNode root = MAPPER.readTree(result);
        assertThat(root.get("name").isTextual()).isTrue();
        assertThat(root.get("name").asText()).isEqualTo("test");
        assertThat(root.get("count").isIntegralNumber()).isTrue();
        assertThat(root.get("enabled").isBoolean()).isTrue();
    }

    @Test
    void stringDefaultPreservedAsString() throws Exception {
        String schema = """
                {"properties":{"name":{"type":"string","default":"hello"}}}""";

        String result = JsonSchemaDefaults.buildDefaultArgumentsJson(schema);

        JsonNode node = MAPPER.readTree(result).get("name");
        assertThat(node.isTextual()).isTrue();
        assertThat(node.asText()).isEqualTo("hello");
    }

    @Test
    void integerDefaultPreservedAsNativeInteger() throws Exception {
        String schema = """
                {"properties":{"count":{"type":"integer","default":42}}}""";

        String result = JsonSchemaDefaults.buildDefaultArgumentsJson(schema);

        JsonNode node = MAPPER.readTree(result).get("count");
        assertThat(node.isIntegralNumber()).isTrue();
        assertThat(node.asLong()).isEqualTo(42L);
    }

    @Test
    void numberDefaultPreservedAsNativeNumber() throws Exception {
        String schema = """
                {"properties":{"ratio":{"type":"number","default":1.5}}}""";

        String result = JsonSchemaDefaults.buildDefaultArgumentsJson(schema);

        JsonNode node = MAPPER.readTree(result).get("ratio");
        assertThat(node.isNumber()).isTrue();
        assertThat(node.isTextual()).isFalse();
        assertThat(node.asDouble()).isEqualTo(1.5);
    }

    @Test
    void booleanDefaultPreservedAsNativeBoolean() throws Exception {
        String schema = """
                {"properties":{"enabled":{"type":"boolean","default":false}}}""";

        String result = JsonSchemaDefaults.buildDefaultArgumentsJson(schema);

        JsonNode node = MAPPER.readTree(result).get("enabled");
        assertThat(node.isBoolean()).isTrue();
        assertThat(node.asBoolean()).isFalse();
    }

    @Test
    void emptyPropertiesReturnsEmptyObject() {
        String schema = """
                {"properties":{}}""";

        String result = JsonSchemaDefaults.buildDefaultArgumentsJson(schema);

        assertThat(result).isEqualTo("{}");
    }

    @Test
    void schemaWithNoPropertiesFieldReturnsEmptyObject() {
        String schema = """
                {"type":"object"}""";

        String result = JsonSchemaDefaults.buildDefaultArgumentsJson(schema);

        assertThat(result).isEqualTo("{}");
    }

    @Test
    void enumPicksFirstValue() throws Exception {
        String schema = """
                {"properties":{"state":{"type":"string","enum":["published","draft","archived","closed"]}}}""";

        String result = JsonSchemaDefaults.buildDefaultArgumentsJson(schema);

        JsonNode node = MAPPER.readTree(result).get("state");
        assertThat(node.isTextual()).isTrue();
        assertThat(node.asText()).isEqualTo("published");
    }

    @Test
    void enumOnIntegerPicksFirstValueVerbatim() throws Exception {
        String schema = """
                {"properties":{"priority":{"type":"integer","enum":[3,1,2]}}}""";

        String result = JsonSchemaDefaults.buildDefaultArgumentsJson(schema);

        JsonNode node = MAPPER.readTree(result).get("priority");
        assertThat(node.isIntegralNumber()).isTrue();
        assertThat(node.asInt()).isEqualTo(3);
    }

    @Test
    void minimumOnInteger() throws Exception {
        String schema = """
                {"properties":{"limit":{"type":"integer","minimum":10}}}""";

        String result = JsonSchemaDefaults.buildDefaultArgumentsJson(schema);

        JsonNode node = MAPPER.readTree(result).get("limit");
        assertThat(node.isIntegralNumber()).isTrue();
        assertThat(node.asLong()).isEqualTo(10L);
    }

    @Test
    void minimumOnNumber() throws Exception {
        String schema = """
                {"properties":{"limit":{"type":"number","minimum":10}}}""";

        String result = JsonSchemaDefaults.buildDefaultArgumentsJson(schema);

        JsonNode node = MAPPER.readTree(result).get("limit");
        assertThat(node.isNumber()).isTrue();
        assertThat(node.asDouble()).isEqualTo(10.0);
    }

    @Test
    void minLengthOnStringPadsToRequiredLength() throws Exception {
        String schema = """
                {"properties":{"slug":{"type":"string","minLength":8}}}""";

        String result = JsonSchemaDefaults.buildDefaultArgumentsJson(schema);

        JsonNode node = MAPPER.readTree(result).get("slug");
        assertThat(node.isTextual()).isTrue();
        assertThat(node.asText().length()).isGreaterThanOrEqualTo(8);
    }

    @Test
    void emailFormat() throws Exception {
        String schema = """
                {"properties":{"contact":{"type":"string","format":"email"}}}""";

        String result = JsonSchemaDefaults.buildDefaultArgumentsJson(schema);

        JsonNode node = MAPPER.readTree(result).get("contact");
        assertThat(node.asText()).isEqualTo("test@example.com");
    }

    @Test
    void nestedObjectGetsAllProperties() throws Exception {
        String schema = """
                {"properties":{"telemetry":{"type":"object","properties":{"intent":{"type":"string"}}}}}""";

        String result = JsonSchemaDefaults.buildDefaultArgumentsJson(schema);

        JsonNode telemetry = MAPPER.readTree(result).get("telemetry");
        assertThat(telemetry.isObject()).isTrue();
        assertThat(telemetry.get("intent").asText()).isEqualTo("test");
    }

    @Test
    void nestedObjectIncludesBothRequiredAndOptionalProperties() throws Exception {
        String schema = """
                {"properties":{"config":{"type":"object","required":["a"],"properties":{"a":{"type":"string"},"b":{"type":"integer"}}}}}""";

        String result = JsonSchemaDefaults.buildDefaultArgumentsJson(schema);

        JsonNode config = MAPPER.readTree(result).get("config");
        assertThat(config.has("a")).isTrue();
        assertThat(config.has("b")).isTrue();
    }

    @Test
    void arrayWithMinItems() throws Exception {
        String schema = """
                {"properties":{"tags":{"type":"array","minItems":1,"items":{"type":"string"}}}}""";

        String result = JsonSchemaDefaults.buildDefaultArgumentsJson(schema);

        JsonNode tags = MAPPER.readTree(result).get("tags");
        assertThat(tags.isArray()).isTrue();
        assertThat(tags.size()).isEqualTo(1);
        assertThat(tags.get(0).asText()).isEqualTo("test");
    }

    @Test
    void arrayWithoutMinItemsIsEmpty() throws Exception {
        String schema = """
                {"properties":{"tags":{"type":"array","items":{"type":"string"}}}}""";

        String result = JsonSchemaDefaults.buildDefaultArgumentsJson(schema);

        JsonNode tags = MAPPER.readTree(result).get("tags");
        assertThat(tags.isArray()).isTrue();
        assertThat(tags.size()).isZero();
    }

    @Test
    void oneOfResolvesToFirstSubSchema() throws Exception {
        String schema = """
                {"properties":{"value":{"oneOf":[{"type":"string"},{"type":"integer"}]}}}""";

        String result = JsonSchemaDefaults.buildDefaultArgumentsJson(schema);

        JsonNode node = MAPPER.readTree(result).get("value");
        assertThat(node.isTextual()).isTrue();
        assertThat(node.asText()).isEqualTo("test");
    }

    @Test
    void anyOfResolvesToFirstSubSchema() throws Exception {
        String schema = """
                {"properties":{"value":{"anyOf":[{"type":"integer"},{"type":"string"}]}}}""";

        String result = JsonSchemaDefaults.buildDefaultArgumentsJson(schema);

        JsonNode node = MAPPER.readTree(result).get("value");
        assertThat(node.isIntegralNumber()).isTrue();
    }

    @Test
    void allOfResolvesToFirstSubSchema() throws Exception {
        String schema = """
                {"properties":{"value":{"allOf":[{"type":"string"},{"minLength":1}]}}}""";

        String result = JsonSchemaDefaults.buildDefaultArgumentsJson(schema);

        JsonNode node = MAPPER.readTree(result).get("value");
        assertThat(node.isTextual()).isTrue();
    }

    @Test
    void explicitDefaultWinsOverEnum() throws Exception {
        String schema = """
                {"properties":{"choice":{"type":"string","default":"foo","enum":["bar","baz"]}}}""";

        String result = JsonSchemaDefaults.buildDefaultArgumentsJson(schema);

        JsonNode node = MAPPER.readTree(result).get("choice");
        assertThat(node.asText()).isEqualTo("foo");
    }

    @Test
    void booleanDefaultTrueRespectedOverFalseFallback() throws Exception {
        String schema = """
                {"properties":{"enabled":{"type":"boolean","default":true}}}""";

        String result = JsonSchemaDefaults.buildDefaultArgumentsJson(schema);

        JsonNode node = MAPPER.readTree(result).get("enabled");
        assertThat(node.asBoolean()).isTrue();
    }

    @Test
    void complexFixtureMatchesWorkableGetJobsShape() throws Exception {
        String schema = """
                {"type":"object","properties":{
                    "account":{"type":"string"},
                    "limit":{"type":"number","minimum":10},
                    "since_id":{"type":"string"},
                    "state":{"type":"string","enum":["published","draft","archived","closed"]},
                    "telemetry":{"type":"object","required":["intent"],"properties":{"intent":{"type":"string"}}}
                }}""";

        String result = JsonSchemaDefaults.buildDefaultArgumentsJson(schema);

        JsonNode root = MAPPER.readTree(result);
        assertThat(root.get("account").asText()).isEqualTo("test");
        assertThat(root.get("limit").asDouble()).isEqualTo(10.0);
        assertThat(root.get("since_id").asText()).isEqualTo("test");
        assertThat(root.get("state").asText()).isEqualTo("published");
        assertThat(root.get("telemetry").isObject()).isTrue();
        assertThat(root.get("telemetry").get("intent").asText()).isEqualTo("test");
    }

    @Test
    void arrayMinItemsRecursesIntoComplexItemSchema() throws Exception {
        String schema = """
                {"properties":{"records":{"type":"array","minItems":1,"items":{"type":"object","properties":{"id":{"type":"integer"}}}}}}""";

        String result = JsonSchemaDefaults.buildDefaultArgumentsJson(schema);

        JsonNode records = MAPPER.readTree(result).get("records");
        assertThat(records.size()).isEqualTo(1);
        assertThat(records.get(0).get("id").isIntegralNumber()).isTrue();
    }

    @Test
    void malformedSchemaFallsBackToEmptyArgumentsObject() {
        String result = JsonSchemaDefaults.buildDefaultArgumentsJson("not-valid-json");

        assertThat(result).isEqualTo("{}");
    }
}
