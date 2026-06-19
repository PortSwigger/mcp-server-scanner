package com.mcpscanner.scan;

import com.fasterxml.jackson.core.JsonFactory;
import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.core.JsonToken;

import java.io.IOException;
import java.util.Optional;

/**
 * Locates the byte range of the {@code params.uri} string inside a UTF-8 encoded
 * JSON-RPC {@code resources/read} body using Jackson's streaming parser.
 *
 * <p>The outer range {@code [startInclusive, endExclusive)} INCLUDES the surrounding
 * double quotes; the {@link UriValueRange#innerStartInclusive()} /
 * {@link UriValueRange#innerEndExclusive()} accessors trim them so callers can target
 * the URI content directly.
 */
public final class UriValueLocator {

    private static final JsonFactory FACTORY = new JsonFactory();
    private static final String PARAMS_FIELD = "params";
    private static final String URI_FIELD = "uri";

    private UriValueLocator() {}

    public record UriValueRange(int startInclusive, int endExclusive) {

        public int innerStartInclusive() {
            return startInclusive + 1;
        }

        public int innerEndExclusive() {
            return endExclusive - 1;
        }
    }

    public static Optional<UriValueRange> locate(byte[] bodyBytes) {
        if (bodyBytes == null || bodyBytes.length == 0) {
            return Optional.empty();
        }
        try (JsonParser parser = FACTORY.createParser(bodyBytes)) {
            return locateUriWithinParams(parser, bodyBytes);
        } catch (IOException | IllegalStateException e) {
            return Optional.empty();
        }
    }

    private static Optional<UriValueRange> locateUriWithinParams(JsonParser parser, byte[] bodyBytes) throws IOException {
        while (parser.nextToken() != null) {
            if (isParamsObjectStart(parser)) {
                return locateUriField(parser, bodyBytes);
            }
        }
        return Optional.empty();
    }

    private static boolean isParamsObjectStart(JsonParser parser) throws IOException {
        return parser.currentToken() == JsonToken.FIELD_NAME
                && PARAMS_FIELD.equals(parser.currentName())
                && parser.nextToken() == JsonToken.START_OBJECT;
    }

    private static Optional<UriValueRange> locateUriField(JsonParser parser, byte[] bodyBytes) throws IOException {
        while (parser.nextToken() == JsonToken.FIELD_NAME) {
            String name = parser.currentName();
            JsonToken value = parser.nextToken();
            if (URI_FIELD.equals(name) && value == JsonToken.VALUE_STRING) {
                int start = (int) parser.currentTokenLocation().getByteOffset();
                return Optional.of(new UriValueRange(start, findClosingQuote(bodyBytes, start) + 1));
            }
            parser.skipChildren();
        }
        return Optional.empty();
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
}
