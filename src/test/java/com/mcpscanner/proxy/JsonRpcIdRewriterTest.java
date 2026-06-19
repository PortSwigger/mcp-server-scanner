package com.mcpscanner.proxy;

import com.fasterxml.jackson.databind.JsonNode;
import com.mcpscanner.mcp.McpObjectMapper;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.concurrent.atomic.AtomicLong;
import java.util.function.LongSupplier;

import static org.assertj.core.api.Assertions.assertThat;

class JsonRpcIdRewriterTest {

    private AtomicLong counter;
    private JsonRpcIdRewriter rewriter;

    @BeforeEach
    void setUp() {
        counter = new AtomicLong(1000);
        LongSupplier idAllocator = counter::incrementAndGet;
        rewriter = new JsonRpcIdRewriter(idAllocator, null);
    }

    @Test
    void rewritesIdInSingleObjectBody() throws Exception {
        String body = "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/list\"}";

        String rewritten = rewriter.rewrite(body);

        JsonNode node = McpObjectMapper.INSTANCE.readTree(rewritten);
        assertThat(node.get("id").asLong()).isEqualTo(1001L);
        assertThat(node.get("method").asText()).isEqualTo("tools/list");
    }

    @Test
    void leavesObjectWithoutIdUnchanged() {
        String body = "{\"jsonrpc\":\"2.0\",\"method\":\"notifications/initialized\"}";

        String rewritten = rewriter.rewrite(body);

        assertThat(rewritten).isEqualTo(body);
    }

    @Test
    void rewritesIdsInBatchArrayBody() throws Exception {
        String body = "[" +
                "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/list\"}," +
                "{\"jsonrpc\":\"2.0\",\"method\":\"notifications/initialized\"}," +
                "{\"jsonrpc\":\"2.0\",\"id\":\"abc\",\"method\":\"tools/call\"}" +
                "]";

        String rewritten = rewriter.rewrite(body);

        JsonNode array = McpObjectMapper.INSTANCE.readTree(rewritten);
        assertThat(array.isArray()).isTrue();
        assertThat(array).hasSize(3);
        assertThat(array.get(0).get("id").asLong()).isEqualTo(1001L);
        assertThat(array.get(1).has("id")).isFalse();
        assertThat(array.get(2).get("id").asLong()).isEqualTo(1002L);
    }

    @Test
    void leavesEmptyBodyUnchanged() {
        assertThat(rewriter.rewrite("")).isEqualTo("");
        assertThat(rewriter.rewrite(null)).isNull();
    }

    @Test
    void leavesNonJsonBodyUnchanged() {
        String body = "not-json";

        String rewritten = rewriter.rewrite(body);

        assertThat(rewritten).isEqualTo(body);
    }
}
