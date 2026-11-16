package com.mcpscanner.scan;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.mcpscanner.mcp.McpPromptDefinition;
import com.mcpscanner.mcp.PromptArgument;
import com.mcpscanner.testutil.MontoyaTestFactory;

import java.util.List;
import java.util.Map;
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
    void defaultArgumentsGivesEveryPropertyAndRequiredArgumentsOnlyTheRequiredOrDefaultedOnes() {
        String schema = """
                {"properties":{"id":{"type":"string"},"limit":{"type":"integer","default":5},
                "note":{"type":"string"}},"required":["id"]}""";

        assertThat(JsonSchemaDefaults.defaultArguments(schema).fieldNames()).toIterable()
                .containsExactlyInAnyOrder("id", "limit", "note");
        assertThat(JsonSchemaDefaults.requiredArguments(schema).fieldNames()).toIterable()
                .containsExactlyInAnyOrder("id", "limit");
    }

    @Test
    void anUnreadableSchemaHasNoArguments() {
        assertThat(JsonSchemaDefaults.defaultArguments("not json").isEmpty()).isTrue();
        assertThat(JsonSchemaDefaults.requiredArguments("not json").isEmpty()).isTrue();
    }

    @Test
    void everyPromptArgumentGetsThePlaceholder() {
        McpPromptDefinition prompt = new McpPromptDefinition("summary", "",
                List.of(new PromptArgument("topic", "", true), new PromptArgument("tone", "", false)));

        assertThat(PromptDefaults.arguments(prompt).toString()).isEqualTo("{\"topic\":\"test\",\"tone\":\"test\"}");
    }

    @Test
    void stringPropertyDefaultsToTest() {
        String schema = """
                {"properties":{"name":{"type":"string"}}}""";

        String result = JsonSchemaDefaults.buildDefaultArgumentsJson(schema);

        assertThat(result).isEqualTo("{\"name\":\"test\"}");
    }

    @Test
    void topLevelAnyOfTakesItsFirstBranchsArguments() {
        String schema = """
                {"anyOf":[{"type":"object","properties":{"project_id":{"type":"string"}}},
                          {"type":"object","properties":{"group_id":{"type":"string"}}}]}""";

        String result = JsonSchemaDefaults.buildDefaultArgumentsJson(schema);

        assertThat(result).isEqualTo("{\"project_id\":\"test\"}");
    }

    @Test
    void nullableTypeArrayTakesItsNonNullType() throws Exception {
        String schema = """
                {"properties":{"ref":{"type":["null","string"]},"count":{"type":["integer","null"]},
                               "mode":{"type":["string","null"],"enum":[]}}}""";

        String result = JsonSchemaDefaults.buildDefaultArgumentsJson(schema);

        assertThat(MAPPER.readTree(result)).isEqualTo(MAPPER.readTree("{\"ref\":\"test\",\"count\":1,\"mode\":\"test\"}"));
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
    void arrayPropertyWithoutItemSchemaDefaultsToEmptyArray() {
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
                {"properties":{"limit":{"type":"integer","minimum":10}},"required":["limit"]}""";

        String result = JsonSchemaDefaults.buildDefaultArgumentsJson(schema);

        JsonNode node = MAPPER.readTree(result).get("limit");
        assertThat(node.isIntegralNumber()).isTrue();
        assertThat(node.asLong()).isEqualTo(10L);
    }

    @Test
    void minimumOnNumber() throws Exception {
        String schema = """
                {"properties":{"limit":{"type":"number","minimum":10}},"required":["limit"]}""";

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
    void optionalStringArrayCarriesOnePlaceholderElementSoItsItemCanBeFuzzed() throws Exception {
        String schema = """
                {"properties":{"tags":{"type":"array","items":{"type":"string"}}}}""";

        JsonNode tags = MAPPER.readTree(JsonSchemaDefaults.buildDefaultArgumentsJson(schema)).get("tags");

        assertThat(tags).hasSize(1);
        assertThat(tags.get(0).asText()).isEqualTo("test");
    }

    @Test
    void nullableStringArrayWithNullDefaultCarriesOnePlaceholderElement() throws Exception {
        String schema = """
                {"properties":{"files":{"anyOf":[{"items":{"type":"string"},"type":"array"},{"type":"null"}],
                "default":null,"title":"Files"}}}""";

        JsonNode files = MAPPER.readTree(JsonSchemaDefaults.buildDefaultArgumentsJson(schema)).get("files");

        assertThat(files).hasSize(1);
        assertThat(files.get(0).asText()).isEqualTo("test");
    }

    @Test
    void nullableScalarWithNullDefaultStaysNull() throws Exception {
        String schema = """
                {"properties":{"model":{"anyOf":[{"type":"string"},{"type":"null"}],"default":null}}}""";

        assertThat(MAPPER.readTree(JsonSchemaDefaults.buildDefaultArgumentsJson(schema)).get("model").isNull())
                .isTrue();
    }

    @Test
    void arrayWithoutItemSchemaStaysEmpty() throws Exception {
        String schema = """
                {"properties":{"tags":{"type":"array"}}}""";

        assertThat(MAPPER.readTree(JsonSchemaDefaults.buildDefaultArgumentsJson(schema)).get("tags")).isEmpty();
    }

    @Test
    void stringArrayThatMayHoldNoItemsStaysEmpty() throws Exception {
        String schema = """
                {"properties":{"tags":{"type":"array","maxItems":0,"items":{"type":"string"}}}}""";

        assertThat(MAPPER.readTree(JsonSchemaDefaults.buildDefaultArgumentsJson(schema)).get("tags")).isEmpty();
    }

    @Test
    void directoryNamedStringIsTheWorkingDirectory() throws Exception {
        String schema = """
                {"properties":{"directory":{"title":"Directory","type":"string"},"query":{"type":"string"}},
                "required":["query","directory"]}""";

        JsonNode arguments = MAPPER.readTree(JsonSchemaDefaults.buildDefaultArgumentsJson(schema));

        assertThat(arguments.get("directory").asText()).isEqualTo("/tmp");
        assertThat(arguments.get("query").asText()).isEqualTo("test");
    }

    @Test
    void stringNamedAfterAWorkingDirectoryIsTheWorkingDirectory() throws Exception {
        String schema = """
                {"properties":{"working_dir":{"type":"string"},"cwd":{"type":"string"},"folder":{"type":"string"}}}""";

        JsonNode arguments = MAPPER.readTree(JsonSchemaDefaults.buildDefaultArgumentsJson(schema));

        assertThat(arguments.get("working_dir").asText()).isEqualTo("/tmp");
        assertThat(arguments.get("cwd").asText()).isEqualTo("/tmp");
        assertThat(arguments.get("folder").asText()).isEqualTo("/tmp");
    }

    @Test
    void directoryNamedStringWithAFormatKeepsTheFormatPlaceholder() throws Exception {
        String schema = """
                {"properties":{"directory":{"type":"string","format":"uri"}}}""";

        assertThat(MAPPER.readTree(JsonSchemaDefaults.buildDefaultArgumentsJson(schema)).get("directory").asText())
                .isEqualTo("https://example.com/");
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
                },"required":["limit"]}""";

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

    @Test
    void aToolboxSqlToolGetsAHarmlessReadForItsRequiredSql() {
        String schema = """
                {"type":"object","properties":{"sql":{"type":"string","description":"The sql to execute."}},
                "required":["sql"]}""";

        assertThat(JsonSchemaDefaults.requiredArguments(schema).toString()).isEqualTo("{\"sql\":\"SELECT 1\"}");
        assertThat(JsonSchemaDefaults.defaultArguments(schema).toString()).isEqualTo("{\"sql\":\"SELECT 1\"}");
    }

    @Test
    void sqlNamedPropertiesInAnyCaseGetTheHarmlessRead() {
        String schema = """
                {"properties":{"rawSQL":{"type":"string"},"sql_statement":{"type":"string"}}}""";

        assertThat(JsonSchemaDefaults.defaultArguments(schema).toString())
                .isEqualTo("{\"rawSQL\":\"SELECT 1\",\"sql_statement\":\"SELECT 1\"}");
    }

    @Test
    void requiredArgumentsKeepOptionalPropertiesOmitted() {
        String schema = """
                {"properties":{"sql":{"type":"string"},"limit":{"type":"integer"}},"required":["sql"]}""";

        assertThat(JsonSchemaDefaults.requiredArguments(schema).fieldNames()).toIterable().containsExactly("sql");
    }

    @Test
    void constIsUsedVerbatim() {
        String schema = """
                {"properties":{"kind":{"type":"string","const":"report"}}}""";

        assertThat(JsonSchemaDefaults.defaultArguments(schema).path("kind").asText()).isEqualTo("report");
    }

    @Test
    void firstExampleIsUsedWhenNoDefaultOrEnum() {
        String schema = """
                {"properties":{"region":{"type":"string","examples":["eu-west-1","us-east-1"]}}}""";

        assertThat(JsonSchemaDefaults.defaultArguments(schema).path("region").asText()).isEqualTo("eu-west-1");
    }

    @Test
    void wellKnownStringFormatsGetValidPlaceholders() {
        String schema = """
                {"properties":{"site":{"type":"string","format":"uri"},"id":{"type":"string","format":"uuid"},
                "at":{"type":"string","format":"date-time"},"day":{"type":"string","format":"date"}}}""";

        JsonNode arguments = JsonSchemaDefaults.defaultArguments(schema);

        assertThat(arguments.path("site").asText()).isEqualTo("https://example.com/");
        assertThat(java.util.UUID.fromString(arguments.path("id").asText())).isNotNull();
        assertThat(java.time.OffsetDateTime.parse(arguments.path("at").asText())).isNotNull();
        assertThat(java.time.LocalDate.parse(arguments.path("day").asText())).isNotNull();
    }

    @Test
    void maxLengthShortensThePlaceholderButNeverEmptiesIt() {
        String schema = """
                {"properties":{"code":{"type":"string","maxLength":2},"tiny":{"type":"string","maxLength":0}}}""";

        JsonNode arguments = JsonSchemaDefaults.defaultArguments(schema);

        assertThat(arguments.path("code").asText()).isEqualTo("te");
        assertThat(arguments.path("tiny").asText()).isEqualTo("t");
    }

    @Test
    void numbersRespectMaximumAndExclusiveBounds() {
        String schema = """
                {"properties":{"negative":{"type":"integer","maximum":-3},
                "positive":{"type":"integer","exclusiveMinimum":4},
                "belowOne":{"type":"integer","exclusiveMaximum":1},
                "ratio":{"type":"number","maximum":0.25}},"required":["negative","positive","belowOne","ratio"]}""";

        JsonNode arguments = JsonSchemaDefaults.defaultArguments(schema);

        assertThat(arguments.path("negative").asLong()).isEqualTo(-3L);
        assertThat(arguments.path("positive").asLong()).isEqualTo(5L);
        assertThat(arguments.path("belowOne").asLong()).isZero();
        assertThat(arguments.path("ratio").asDouble()).isEqualTo(0.25);
    }

    @Test
    void urlNamedStringIsAnAbsoluteUrlSoTheServerDoesNotRejectItAsMalformed() throws Exception {
        String schema = """
                {"properties":{"url":{"type":"string","minLength":1},"imageUrl":{"type":"string"},
                "target_url":{"type":"string"},"curl_options":{"type":"string"}}}""";

        JsonNode arguments = MAPPER.readTree(JsonSchemaDefaults.buildDefaultArgumentsJson(schema));

        assertThat(arguments.get("url").asText()).isEqualTo("https://example.com/");
        assertThat(arguments.get("imageUrl").asText()).isEqualTo("https://example.com/");
        assertThat(arguments.get("target_url").asText()).isEqualTo("https://example.com/");
        assertThat(arguments.get("curl_options").asText()).isEqualTo("test");
    }

    @Test
    void optionalNumbersWithoutALowerBoundAreKeptWhateverTheirName() throws Exception {
        String schema = """
                {"properties":{"url":{"type":"string"},"timeout_seconds":{"type":"integer"},
                "maxTier":{"type":"integer"}},"required":["url"]}""";

        JsonNode arguments = MAPPER.readTree(JsonSchemaDefaults.buildDefaultArgumentsJson(schema));

        assertThat(arguments.has("timeout_seconds")).isTrue();
        assertThat(arguments.has("maxTier")).isTrue();
        assertThat(arguments.has("url")).isTrue();
    }

    @Test
    void optionalNumberKnownOnlyByItsLowerBoundIsOmittedBecauseTheBoundStarvesTheCall() throws Exception {
        String schema = """
                {"properties":{"url":{"type":"string"},"maxTimeout":{"type":"integer","exclusiveMinimum":0},
                "retries":{"type":"integer","minimum":0},"pageSize":{"type":"integer","minimum":1,"default":20},
                "limit":{"type":"integer","minimum":1,"examples":[10]}},
                "required":["url"]}""";

        JsonNode arguments = MAPPER.readTree(JsonSchemaDefaults.buildDefaultArgumentsJson(schema));

        assertThat(arguments.has("maxTimeout")).isFalse();
        assertThat(arguments.has("retries")).isFalse();
        assertThat(arguments.get("pageSize").asInt()).isEqualTo(20);
        assertThat(arguments.get("limit").asInt()).isEqualTo(10);
    }

    @Test
    void requiredNumberKnownOnlyByItsLowerBoundIsKept() throws Exception {
        String schema = """
                {"properties":{"maxTimeout":{"type":"integer","exclusiveMinimum":0}},"required":["maxTimeout"]}""";

        JsonNode arguments = MAPPER.readTree(JsonSchemaDefaults.buildDefaultArgumentsJson(schema));

        assertThat(arguments.get("maxTimeout").asInt()).isEqualTo(1);
    }

    @Test
    void directoryPlaceholderIsTheSharedScratchDirectoryBecauseAServerRejectsAPathThatDoesNotExist() throws Exception {
        String schema = """
                {"properties":{"directory":{"type":"string"},"cwd":{"type":"string"}}}""";

        JsonNode arguments = MAPPER.readTree(JsonSchemaDefaults.buildDefaultArgumentsJson(schema));

        assertThat(arguments.get("directory").asText()).isEqualTo("/tmp");
        assertThat(arguments.get("cwd").asText()).isEqualTo("/tmp");
    }

    @Test
    void optionalPatternConstrainedStringWithoutDefaultIsOmittedBecauseItNamesAnExistingThing() throws Exception {
        String schema = """
                {"properties":{"url":{"type":"string"},"sessionId":{"type":"string","pattern":"^[a-z]{1,8}$"}},
                "required":["url"]}""";

        JsonNode arguments = MAPPER.readTree(JsonSchemaDefaults.buildDefaultArgumentsJson(schema));

        assertThat(arguments.has("sessionId")).isFalse();
    }

    @Test
    void requiredAndDefaultedTimeoutsAreKept() throws Exception {
        String schema = """
                {"properties":{"timeout":{"type":"integer","minimum":5},"read_timeout":{"type":"integer","default":10}},
                "required":["timeout"]}""";

        JsonNode arguments = MAPPER.readTree(JsonSchemaDefaults.buildDefaultArgumentsJson(schema));

        assertThat(arguments.get("timeout").asInt()).isEqualTo(5);
        assertThat(arguments.get("read_timeout").asInt()).isEqualTo(10);
    }

    @Test
    void optionalFreeTextAndBooleanWithoutDefaultAreKept() throws Exception {
        String schema = """
                {"properties":{"query":{"type":"string"},"note":{"type":"string"},"verbose":{"type":"boolean"}},
                "required":["query"]}""";

        JsonNode arguments = MAPPER.readTree(JsonSchemaDefaults.buildDefaultArgumentsJson(schema));

        assertThat(arguments.has("note")).isTrue();
        assertThat(arguments.has("verbose")).isTrue();
    }

    @Test
    void trawlScrapeSchemaWithholdsOnlyThePatternBoundExistingSessionId() throws Exception {
        String schema = """
                {"$schema":"http://json-schema.org/draft-07/schema#","type":"object","properties":{
                "sessionId":{"description":"Existing browser session created through POST /sessions","type":"string",
                "pattern":"^[a-zA-Z0-9_-]{1,128}$"},
                "url":{"type":"string","minLength":1,"description":"Public HTTP(S) URL"},
                "maxTimeout":{"description":"Maximum operation time in milliseconds","type":"integer",
                "exclusiveMinimum":0,"maximum":9007199254740991},
                "maxTier":{"description":"Highest anti-bot tier TRAWL may use","anyOf":[{"type":"number","const":1},
                {"type":"number","const":2},{"type":"number","const":3},{"type":"number","const":4}]},
                "skipHttp":{"type":"boolean"},"solveEmbeddedCaptchas":{"type":"boolean"}},
                "required":["url"],"additionalProperties":false}""";

        JsonNode arguments = MAPPER.readTree(JsonSchemaDefaults.buildDefaultArgumentsJson(schema));

        assertThat(arguments.get("url").asText()).isEqualTo("https://example.com/");
        assertThat(arguments.has("sessionId")).isFalse();
        assertThat(arguments.get("maxTier").asInt()).isEqualTo(1);
    }

    @Test
    void optionalFieldsLeftOutOfTheBaseCallAreReportedWithTheirPlaceholders() {
        String schema = """
                {"properties":{"url":{"type":"string"},"sort":{"type":"string","pattern":"^[a-z_]+$"},
                "maxTimeout":{"type":"integer","exclusiveMinimum":0},"note":{"type":"string"}},"required":["url"]}""";

        assertThat(JsonSchemaDefaults.withheldArguments(schema)).containsOnlyKeys(ArgumentPath.of("sort"), ArgumentPath.of("maxTimeout"))
                .containsEntry(ArgumentPath.of("sort"), MAPPER.getNodeFactory().textNode("test"));
    }

    @Test
    void requiredAndDefaultedFieldsAreNeverReportedAsWithheld() {
        String schema = """
                {"properties":{"id":{"type":"string","pattern":"^a$"},"t":{"type":"integer","default":3}},
                "required":["id"]}""";

        assertThat(JsonSchemaDefaults.withheldArguments(schema)).isEmpty();
    }

    @Test
    void aPatternBoundFieldInsideAnObjectArgumentIsReportedWithItsFullPath() {
        String schema = """
                {"properties":{"filter":{"type":"object","properties":{"name":{"type":"string"},
                "ref":{"type":"string","pattern":"^[a-z]+$"},
                "inner":{"type":"object","properties":{"id":{"type":"string","pattern":"^[0-9]+$"}}}}}}}""";

        assertThat(JsonSchemaDefaults.withheldArguments(schema))
                .containsOnlyKeys(ArgumentPath.of("filter", "ref"), ArgumentPath.of("filter", "inner", "id"));
        assertThat(JsonSchemaDefaults.defaultArguments(schema).at("/filter/name").asText()).isEqualTo("test");
        assertThat(JsonSchemaDefaults.defaultArguments(schema).at("/filter").has("ref")).isFalse();
    }

    @Test
    void aPatternBoundFieldInsideArrayItemsIsReportedAtTheFirstItem() {
        String schema = """
                {"properties":{"rows":{"type":"array","items":{"type":"object","properties":
                {"id":{"type":"string"},"ref":{"type":"string","pattern":"^[a-z]+$"}}}}}}""";

        Map<ArgumentPath, JsonNode> withheld = JsonSchemaDefaults.withheldArguments(schema);

        assertThat(withheld).containsOnlyKeys(ArgumentPath.of("rows").firstItem().child("ref"));
        ObjectNode probe = JsonSchemaDefaults.defaultArguments(schema);
        withheld.forEach((path, value) -> path.setIn(probe, value));
        assertThat(probe.at("/rows/0/ref").asText()).isEqualTo("test");
        assertThat(probe.at("/rows")).hasSize(1);
    }

    @Test
    void aPatternBoundFieldInsideAnArrayThatMayHoldNoItemIsNotReported() {
        String schema = """
                {"properties":{"rows":{"type":"array","maxItems":0,"items":{"type":"object","properties":
                {"ref":{"type":"string","pattern":"^[a-z]+$"}}}}}}""";

        assertThat(JsonSchemaDefaults.withheldArguments(schema)).isEmpty();
    }

    @Test
    void aDefaultedObjectArgumentIsNotWalkedForWithheldFields() {
        String schema = """
                {"properties":{"filter":{"type":"object","default":{"a":"b"},
                "properties":{"ref":{"type":"string","pattern":"^[a-z]+$"}}}}}""";

        assertThat(JsonSchemaDefaults.withheldArguments(schema)).isEmpty();
    }
}
