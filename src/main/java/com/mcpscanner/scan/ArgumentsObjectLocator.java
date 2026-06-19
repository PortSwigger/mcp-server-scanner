package com.mcpscanner.scan;

import com.fasterxml.jackson.core.JsonFactory;
import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.core.JsonToken;

import java.io.IOException;
import java.util.Optional;

/**
 * Locates the byte range of the {@code arguments} object inside a UTF-8 encoded
 * JSON-RPC {@code tools/call} body using Jackson's streaming parser.
 *
 * <p>The returned range {@code [start, end)} brackets the {@code {} ... {@code }}
 * substring so callers can slice it out and hand it to {@link ArgumentValueLocator}.
 */
public final class ArgumentsObjectLocator {

    private static final JsonFactory FACTORY = new JsonFactory();
    private static final String ARGUMENTS_FIELD = "arguments";

    private ArgumentsObjectLocator() {}

    public record ArgumentsObjectRange(int start, int end) {}

    public static Optional<ArgumentsObjectRange> locate(byte[] bodyBytes) {
        if (bodyBytes == null || bodyBytes.length == 0) {
            return Optional.empty();
        }
        try (JsonParser parser = FACTORY.createParser(bodyBytes)) {
            while (parser.nextToken() != null) {
                if (isArgumentsObjectStart(parser)) {
                    int start = (int) parser.currentTokenLocation().getByteOffset();
                    parser.skipChildren();
                    int candidateEnd = (int) parser.currentLocation().getByteOffset();
                    return Optional.of(new ArgumentsObjectRange(start, clampToClosingBrace(bodyBytes, candidateEnd)));
                }
            }
        } catch (IOException e) {
            return Optional.empty();
        }
        return Optional.empty();
    }

    private static boolean isArgumentsObjectStart(JsonParser parser) throws IOException {
        return parser.currentToken() == JsonToken.FIELD_NAME
                && ARGUMENTS_FIELD.equals(parser.currentName())
                && parser.nextToken() == JsonToken.START_OBJECT;
    }

    private static int clampToClosingBrace(byte[] bodyBytes, int candidateEnd) {
        int end = Math.min(candidateEnd, bodyBytes.length);
        while (end > 0 && bodyBytes[end - 1] != '}') {
            end--;
        }
        return end;
    }
}
