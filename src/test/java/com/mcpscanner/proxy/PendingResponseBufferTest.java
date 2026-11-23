package com.mcpscanner.proxy;

import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;

import static org.assertj.core.api.Assertions.assertThat;

class PendingResponseBufferTest {

    @Test
    void evictsOldestResponsesOnceTotalBytesExceedBudget() {
        PendingResponseBuffer buffer = new PendingResponseBuffer();

        assertThat(buffer.put("1", reply("aaaa"), 10)).isEmpty();
        assertThat(buffer.put("2", reply("bbbb"), 10)).isEmpty();
        assertThat(buffer.put("3", reply("cccc"), 10)).containsExactly("1");

        assertThat(buffer.totalBytes()).isEqualTo(8);
        assertThat(buffer.remove("1")).isNull();
        assertThat(buffer.remove("2").json()).isEqualTo("bbbb");
        assertThat(buffer.totalBytes()).isEqualTo(4);
    }

    @Test
    void measuresBudgetInTheBytesOfTheEventAsReceived() {
        PendingResponseBuffer buffer = new PendingResponseBuffer();

        buffer.put("1", new StreamedReply("é", "data: é\r\n\r\n".getBytes(StandardCharsets.UTF_8)), 20);

        assertThat(buffer.totalBytes()).isEqualTo(12);
    }

    @Test
    void replacingAnIdAccountsForTheOldResponse() {
        PendingResponseBuffer buffer = new PendingResponseBuffer();
        buffer.put("1", reply("aaaa"), 10);

        buffer.put("1", reply("bb"), 10);

        assertThat(buffer.totalBytes()).isEqualTo(2);
        assertThat(buffer.size()).isEqualTo(1);
    }

    @Test
    void clearResetsTotal() {
        PendingResponseBuffer buffer = new PendingResponseBuffer();
        buffer.put("1", reply("aaaa"), 10);

        buffer.clear();

        assertThat(buffer.size()).isZero();
        assertThat(buffer.totalBytes()).isZero();
    }

    private static StreamedReply reply(String json) {
        return new StreamedReply(json, json.getBytes(StandardCharsets.UTF_8));
    }
}
