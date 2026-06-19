package com.mcpscanner.scan;

import com.fasterxml.jackson.core.JsonFactory;
import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.core.JsonToken;

import java.io.IOException;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Locates the byte range of every top-level argument value inside a UTF-8 encoded
 * JSON object using Jackson's streaming parser.
 *
 * <p>The returned map preserves insertion order and is keyed by the unescaped property
 * name (so a JSON property {@code "a\"b"} is exposed as the literal key {@code a"b}).
 */
public final class ArgumentValueLocator {

    private static final JsonFactory FACTORY = new JsonFactory();

    private ArgumentValueLocator() {}

    /**
     * Byte range {@code [startInclusive, endExclusive)} of a single JSON value.
     *
     * <p>For {@link ValueKind#STRING} values the outer range INCLUDES the surrounding double
     * quotes; the {@link #innerStartInclusive()} / {@link #innerEndExclusive()} accessors strip
     * them so callers can target the unquoted content without doing the arithmetic themselves.
     * For non-string kinds the inner accessors are equal to the outer offsets.
     * Container ranges ({@link ValueKind#OBJECT}, {@link ValueKind#ARRAY}) cover the entire
     * value from {@code {}/[} to its matching closing token.
     */
    public record ValueByteRange(int startInclusive, int endExclusive, ValueKind kind) {

        public int innerStartInclusive() {
            return kind == ValueKind.STRING ? startInclusive + 1 : startInclusive;
        }

        public int innerEndExclusive() {
            return kind == ValueKind.STRING ? endExclusive - 1 : endExclusive;
        }
    }

    public enum ValueKind { STRING, NUMBER, BOOLEAN, NULL, OBJECT, ARRAY }

    public static Map<String, ValueByteRange> locate(byte[] argumentsJsonBytes) {
        if (argumentsJsonBytes == null || argumentsJsonBytes.length == 0) {
            return Map.of();
        }
        try (JsonParser parser = FACTORY.createParser(argumentsJsonBytes)) {
            if (parser.nextToken() != JsonToken.START_OBJECT) {
                return Map.of();
            }
            return collectFieldRanges(parser, argumentsJsonBytes);
        } catch (IOException | IllegalStateException e) {
            return Map.of();
        }
    }

    private static Map<String, ValueByteRange> collectFieldRanges(JsonParser parser, byte[] bytes) throws IOException {
        Map<String, ValueByteRange> ranges = new LinkedHashMap<>();
        while (parser.nextToken() == JsonToken.FIELD_NAME) {
            String fieldName = parser.currentName();
            JsonToken valueToken = parser.nextToken();
            ranges.put(fieldName, rangeForValue(parser, valueToken, bytes));
        }
        return ranges;
    }

    private static ValueByteRange rangeForValue(JsonParser parser, JsonToken valueToken, byte[] bytes) throws IOException {
        ValueKind kind = kindOf(valueToken);
        int start = (int) parser.currentTokenLocation().getByteOffset();
        int end = switch (valueToken) {
            case VALUE_STRING -> findClosingQuote(bytes, start) + 1;
            case START_OBJECT -> findMatchingClose(bytes, start, '{', '}') + 1;
            case START_ARRAY -> findMatchingClose(bytes, start, '[', ']') + 1;
            default -> findScalarEnd(bytes, start);
        };
        if (valueToken == JsonToken.START_OBJECT || valueToken == JsonToken.START_ARRAY) {
            parser.skipChildren();
        }
        return new ValueByteRange(start, end, kind);
    }

    private static int findClosingQuote(byte[] bytes, int openingQuoteIndex) {
        int i = openingQuoteIndex + 1;
        while (i < bytes.length) {
            byte b = bytes[i];
            if (b == '\\') {
                i += 2;
                continue;
            }
            if (b == '"') {
                return i;
            }
            i++;
        }
        throw new IllegalStateException("Unterminated string value at byte " + openingQuoteIndex);
    }

    private static int findMatchingClose(byte[] bytes, int openIndex, char open, char close) {
        int depth = 0;
        int i = openIndex;
        while (i < bytes.length) {
            byte b = bytes[i];
            if (b == '"') {
                i = findClosingQuote(bytes, i) + 1;
                continue;
            }
            if (b == open) depth++;
            else if (b == close && --depth == 0) return i;
            i++;
        }
        throw new IllegalStateException("Unterminated container at byte " + openIndex);
    }

    private static int findScalarEnd(byte[] bytes, int start) {
        int i = start;
        while (i < bytes.length && !isScalarTerminator(bytes[i])) {
            i++;
        }
        return i;
    }

    private static boolean isScalarTerminator(byte b) {
        return b == ',' || b == '}' || b == ']' || b == ' ' || b == '\t' || b == '\n' || b == '\r';
    }

    private static ValueKind kindOf(JsonToken token) {
        return switch (token) {
            case VALUE_STRING -> ValueKind.STRING;
            case VALUE_NUMBER_INT, VALUE_NUMBER_FLOAT -> ValueKind.NUMBER;
            case VALUE_TRUE, VALUE_FALSE -> ValueKind.BOOLEAN;
            case VALUE_NULL -> ValueKind.NULL;
            case START_OBJECT -> ValueKind.OBJECT;
            case START_ARRAY -> ValueKind.ARRAY;
            default -> throw new IllegalStateException("Unexpected JSON token: " + token);
        };
    }
}
