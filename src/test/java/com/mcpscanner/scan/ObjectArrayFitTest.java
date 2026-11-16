package com.mcpscanner.scan;

import com.fasterxml.jackson.databind.JsonNode;
import com.mcpscanner.mcp.McpObjectMapper;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

class ObjectArrayFitTest {

    private static final String ATTACHMENTS = "{\"type\":\"array\",\"items\":{\"allOf\":[{\"type\":\"object\","
            + "\"properties\":{\"title\":{\"type\":[\"string\",\"null\"]},\"mimeType\":{\"type\":[\"string\",\"null\"]},"
            + "\"size\":{\"type\":[\"number\",\"null\"]}}},{\"anyOf\":[{\"type\":\"object\",\"properties\":{"
            + "\"url\":{\"type\":[\"string\",\"null\"]},\"signedUrl\":{\"type\":[\"string\",\"null\"]},"
            + "\"path\":{\"type\":\"null\"},\"signedPath\":{\"type\":\"null\"}}},{\"type\":\"object\",\"properties\":{"
            + "\"path\":{\"type\":[\"string\",\"null\"]},\"signedPath\":{\"type\":[\"string\",\"null\"]},"
            + "\"url\":{\"type\":\"null\"},\"signedUrl\":{\"type\":\"null\"}}}]}]}}";
    private static final String MINED = "[{\"path\":\"download/a.txt\",\"title\":\"a.txt\",\"mimetype\":\"text/plain\","
            + "\"size\":35,\"id\":\"att1\"}]";

    @Test
    void anArrayOfObjectsDescribesAnObjectArrayWhateverComposesItsItems() {
        assertThat(ObjectArrayFit.describes(json(ATTACHMENTS))).isTrue();
        assertThat(ObjectArrayFit.describes(json("{\"type\":\"array\",\"items\":{\"type\":\"string\"}}"))).isFalse();
        assertThat(ObjectArrayFit.describes(json("{\"type\":\"string\"}"))).isFalse();
    }

    @Test
    void fitsEachElementToTheDeclaredPropertiesMatchingNamesIgnoringCase() {
        JsonNode fitted = ObjectArrayFit.fit(json(ATTACHMENTS), json(MINED));

        assertThat(fitted.get(0)).isEqualTo(json("{\"title\":\"a.txt\",\"mimeType\":\"text/plain\",\"size\":35,"
                + "\"url\":null,\"signedUrl\":null,\"path\":\"download/a.txt\",\"signedPath\":null}"));
    }

    @Test
    void overlapsOnlyWhenAnElementSharesAPropertyWithTheItemSchema() {
        assertThat(ObjectArrayFit.overlaps(json(ATTACHMENTS), json(MINED))).isTrue();
        assertThat(ObjectArrayFit.overlaps(json(ATTACHMENTS), json("[{\"colour\":\"red\"}]"))).isFalse();
        assertThat(ObjectArrayFit.overlaps(json(ATTACHMENTS), json("[]"))).isFalse();
    }

    @Test
    void keepsAtMostAFewElements() {
        JsonNode many = json("[{\"path\":\"1\"},{\"path\":\"2\"},{\"path\":\"3\"},{\"path\":\"4\"},{\"path\":\"5\"},"
                + "{\"path\":\"6\"},{\"path\":\"7\"}]");

        assertThat(ObjectArrayFit.fit(json(ATTACHMENTS), many)).hasSize(ObjectArrayFit.MOST_ELEMENTS);
    }

    private static JsonNode json(String text) {
        try {
            return McpObjectMapper.INSTANCE.readTree(text);
        } catch (Exception malformed) {
            throw new IllegalArgumentException(malformed);
        }
    }
}
