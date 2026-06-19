package com.mcpscanner.mcp;

import com.fasterxml.jackson.core.StreamReadConstraints;
import com.fasterxml.jackson.core.exc.StreamConstraintsException;
import com.fasterxml.jackson.databind.JsonNode;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class McpObjectMapperTest {

    @Test
    void streamReadConstraintsAreConfigured() {
        StreamReadConstraints constraints = McpObjectMapper.INSTANCE.getFactory().streamReadConstraints();

        assertThat(constraints.getMaxDocumentLength()).isPositive();
        assertThat(constraints.getMaxNestingDepth()).isLessThanOrEqualTo(64);
        assertThat(constraints.getMaxStringLength()).isLessThanOrEqualTo(5 * 1024 * 1024);
        assertThat(constraints.getMaxNumberLength()).isPositive();
    }

    @Test
    void rejectsDocumentExceedingMaxLength() {
        int oversize = 20 * 1024 * 1024;
        StringBuilder json = new StringBuilder(oversize + 32);
        json.append("\"");
        for (int i = 0; i < oversize; i++) {
            json.append('a');
        }
        json.append("\"");

        assertThatThrownBy(() -> McpObjectMapper.INSTANCE.readTree(json.toString()))
                .isInstanceOf(StreamConstraintsException.class);
    }

    @Test
    void rejectsExcessiveNestingDepth() {
        int depth = 200;
        StringBuilder json = new StringBuilder();
        for (int i = 0; i < depth; i++) {
            json.append("[");
        }
        for (int i = 0; i < depth; i++) {
            json.append("]");
        }

        assertThatThrownBy(() -> McpObjectMapper.INSTANCE.readTree(json.toString()))
                .isInstanceOf(StreamConstraintsException.class);
    }

    @Test
    void parsesSmallDocumentsNormally() throws Exception {
        JsonNode node = McpObjectMapper.INSTANCE.readTree("{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{\"ok\":true}}");

        assertThat(node.get("id").asInt()).isEqualTo(1);
        assertThat(node.get("result").get("ok").asBoolean()).isTrue();
    }
}
