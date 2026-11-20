package com.mcpscanner.http;

import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.List;
import java.util.Optional;
import java.util.regex.Pattern;

public final class ChunkedBody {

    private static final String CHUNKED = "chunked";
    private static final int MAX_SIZE_DIGITS = 8;
    private static final long INVALID_SIZE = -1;
    private static final Pattern CUT_SIZE_LINE = Pattern.compile("[0-9a-fA-F]{0,8}(;[^\\r\\n]*)?\\r?");
    private static final Pattern CUT_DATA_END = Pattern.compile("\\r?");

    private final byte[] framed;
    private final ByteArrayOutputStream decoded = new ByteArrayOutputStream();
    private int position;

    private ChunkedBody(byte[] framed) {
        this.framed = framed;
    }

    public static byte[] unframe(List<String> transferEncodings, byte[] body) {
        return declaresChunked(transferEncodings) ? new ChunkedBody(body).decode().orElse(body) : body;
    }

    private static boolean declaresChunked(List<String> transferEncodings) {
        List<String> codings = transferEncodings.stream()
                .flatMap(value -> Arrays.stream(value.split(",")))
                .map(String::trim)
                .filter(coding -> !coding.isEmpty())
                .toList();
        return !codings.isEmpty() && codings.get(codings.size() - 1).equalsIgnoreCase(CHUNKED);
    }

    private Optional<byte[]> decode() {
        while (true) {
            Optional<String> sizeLine = nextLine();
            if (sizeLine.isEmpty()) return cutWhere(CUT_SIZE_LINE);
            long size = parseSize(sizeLine.get());
            if (size == INVALID_SIZE) return Optional.empty();
            if (size == 0) return afterLastChunk();
            if (size > framed.length - position) return completeChunksSoFar();
            copyChunk(size);
            Optional<String> dataEnd = nextLine();
            if (dataEnd.isEmpty()) return cutWhere(CUT_DATA_END);
            if (!dataEnd.get().isEmpty()) return Optional.empty();
        }
    }

    private Optional<byte[]> cutWhere(Pattern framingPrefix) {
        String rest = new String(framed, position, framed.length - position, StandardCharsets.ISO_8859_1);
        return framingPrefix.matcher(rest).matches() ? completeChunksSoFar() : Optional.empty();
    }

    private Optional<byte[]> completeChunksSoFar() {
        return decoded.size() == 0 ? Optional.empty() : Optional.of(decoded.toByteArray());
    }

    private static long parseSize(String sizeLine) {
        int extensionStart = sizeLine.indexOf(';');
        String digits = (extensionStart < 0 ? sizeLine : sizeLine.substring(0, extensionStart)).stripTrailing();
        if (digits.isEmpty() || digits.length() > MAX_SIZE_DIGITS || !isHex(digits)) return INVALID_SIZE;
        return Long.parseLong(digits, 16);
    }

    private static boolean isHex(String digits) {
        return digits.chars().allMatch(c -> Character.digit(c, 16) >= 0);
    }

    private void copyChunk(long size) {
        decoded.write(framed, position, (int) size);
        position += (int) size;
    }

    private Optional<byte[]> afterLastChunk() {
        Optional<String> line;
        while ((line = nextLine()).isPresent()) {
            if (line.get().isEmpty()) {
                return position == framed.length ? Optional.of(decoded.toByteArray()) : Optional.empty();
            }
            if (line.get().indexOf(':') <= 0) return Optional.empty();
        }
        return completeChunksSoFar();
    }

    private Optional<String> nextLine() {
        for (int end = position; end < framed.length; end++) {
            if (framed[end] == '\n') {
                int lineEnd = end > position && framed[end - 1] == '\r' ? end - 1 : end;
                String line = new String(framed, position, lineEnd - position, StandardCharsets.ISO_8859_1);
                position = end + 1;
                return Optional.of(line);
            }
        }
        return Optional.empty();
    }
}
