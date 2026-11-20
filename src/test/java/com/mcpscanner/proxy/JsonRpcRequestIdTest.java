package com.mcpscanner.proxy;

import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;

import static org.assertj.core.api.Assertions.assertThat;

class JsonRpcRequestIdTest {

    private static final String CALL = "{\"jsonrpc\":\"2.0\",\"id\":32,\"method\":\"tools/call\","
            + "\"params\":{\"name\":\"t\",\"arguments\":{\"duration\":10}}}";

    @Test
    void aBodyWhoseIdAloneChangedIsTheSameApartFromItsId() {
        assertThat(sameApartFromId(CALL, CALL.replace("\"id\":32", "\"id\":\"32'+payload+'\""))).isTrue();
    }

    @Test
    void anUnchangedBodyIsTheSameApartFromItsId() {
        assertThat(sameApartFromId(CALL, CALL)).isTrue();
    }

    @Test
    void aBodyWhoseArgumentChangedIsNotTheSameApartFromItsId() {
        assertThat(sameApartFromId(CALL, CALL.replace("\"duration\":10", "\"duration\":\"10;id\""))).isFalse();
    }

    @Test
    void aBodyWhoseIdAndArgumentChangedIsNotTheSameApartFromItsId() {
        String altered = CALL.replace("\"id\":32", "\"id\":33").replace("\"duration\":10", "\"duration\":11");

        assertThat(sameApartFromId(CALL, altered)).isFalse();
    }

    @Test
    void aBodyThatIsNotOneJsonObjectIsComparedByItsBytes() {
        assertThat(sameApartFromId("[" + CALL + "]", "[" + CALL.replace("32", "33") + "]")).isFalse();
        assertThat(sameApartFromId("not json", "not json either")).isFalse();
        assertThat(sameApartFromId("not json", "not json")).isTrue();
    }

    private static boolean sameApartFromId(String before, String after) {
        return JsonRpcRequestId.sameApartFromId(before.getBytes(StandardCharsets.UTF_8),
                after.getBytes(StandardCharsets.UTF_8));
    }
}
