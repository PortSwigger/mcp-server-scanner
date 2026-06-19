package com.mcpscanner.ui;

import org.junit.jupiter.api.Test;

import java.util.LinkedHashMap;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class HeaderValidatorTest {

    private final HeaderValidator validator = new HeaderValidator();

    @Test
    void emptyInputYieldsEmptyMap() {
        assertThat(validator.validate(Map.of())).isEmpty();
    }

    @Test
    void wellFormedHeaderPassesThrough() {
        assertThat(validator.validate(Map.of("Foo", "bar"))).containsEntry("Foo", "bar");
    }

    @Test
    void nonReservedHeaderIsAllowed() {
        assertThat(validator.validate(Map.of("X-Custom-Auth", "token123")))
                .containsEntry("X-Custom-Auth", "token123");
    }

    @Test
    void preservesInsertionOrder() {
        Map<String, String> raw = new LinkedHashMap<>();
        raw.put("A", "1");
        raw.put("B", "2");
        raw.put("C", "3");

        assertThat(validator.validate(raw)).containsExactly(
                Map.entry("A", "1"), Map.entry("B", "2"), Map.entry("C", "3"));
    }

    @Test
    void nullValueBecomesEmptyString() {
        Map<String, String> raw = new LinkedHashMap<>();
        raw.put("X-Test", null);

        assertThat(validator.validate(raw)).containsEntry("X-Test", "");
    }

    @Test
    void rejectsReservedAuthorization() {
        assertThatThrownBy(() -> validator.validate(Map.of("Authorization", "Bearer abc")))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("reserved")
                .hasMessageContaining("Authorization");
    }

    @Test
    void rejectsReservedSessionIdCaseInsensitive() {
        assertThatThrownBy(() -> validator.validate(Map.of("MCP-SESSION-ID", "deadbeef")))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("reserved")
                .hasMessageContaining("MCP-SESSION-ID");
    }

    @Test
    void rejectsReservedContentTypeCaseInsensitive() {
        assertThatThrownBy(() -> validator.validate(Map.of("content-TYPE", "application/json")))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("reserved")
                .hasMessageContaining("content-TYPE");
    }

    @Test
    void rejectsReservedAccept() {
        assertThatThrownBy(() -> validator.validate(Map.of("accept", "application/json")))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("reserved")
                .hasMessageContaining("accept");
    }

    @Test
    void rejectsBlankKey() {
        Map<String, String> raw = new LinkedHashMap<>();
        raw.put("   ", "value");

        assertThatThrownBy(() -> validator.validate(raw))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("empty");
    }

    @Test
    void rejectsNullKey() {
        Map<String, String> raw = new LinkedHashMap<>();
        raw.put(null, "value");

        assertThatThrownBy(() -> validator.validate(raw))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("empty");
    }

    @Test
    void rejectsKeyWithNewline() {
        assertThatThrownBy(() -> validator.validate(Map.of("Bad\nKey", "value")))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("Bad");
    }

    @Test
    void rejectsKeyWithCarriageReturn() {
        assertThatThrownBy(() -> validator.validate(Map.of("Bad\rKey", "value")))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("Bad");
    }

    @Test
    void rejectsKeyWithNul() {
        assertThatThrownBy(() -> validator.validate(Map.of("Bad\u0000Key", "value")))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("Bad");
    }

    @Test
    void rejectsValueWithCrlf() {
        assertThatThrownBy(() -> validator.validate(Map.of("X-Smuggle", "foo\r\nX-Injected: bar")))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("X-Smuggle");
    }

    @Test
    void rejectsValueWithNul() {
        assertThatThrownBy(() -> validator.validate(Map.of("X-Test", "foo\u0000bar")))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("X-Test");
    }
}
