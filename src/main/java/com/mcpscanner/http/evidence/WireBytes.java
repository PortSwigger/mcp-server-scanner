package com.mcpscanner.http.evidence;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;

final class WireBytes {

    private WireBytes() {
    }

    private static final byte[] HEAD_END = {'\r', '\n', '\r', '\n'};
    private static final int STATUS_CODE_OFFSET = "HTTP/1.1 ".length();
    private static final int STATUS_CODE_LENGTH = 3;
    private static final String SWITCHING_PROTOCOLS = "101";

    static int bodyStart(byte[] message) {
        return bodyStart(message, 0);
    }

    static int bodyStart(byte[] message, int from) {
        int headEnd = headEnd(message, from);
        return headEnd == message.length ? headEnd : headEnd + HEAD_END.length;
    }

    static int headEnd(byte[] message) {
        return headEnd(message, 0);
    }

    static int finalResponseStart(byte[] read) {
        int start = 0;
        while (isInterim(read, start) && bodyStart(read, start) < read.length) {
            start = bodyStart(read, start);
        }
        return start;
    }

    static byte[] joined(byte[] first, byte[] second) {
        byte[] whole = Arrays.copyOf(first, first.length + second.length);
        System.arraycopy(second, 0, whole, first.length, second.length);
        return whole;
    }

    private static int headEnd(byte[] message, int from) {
        for (int start = from; start + HEAD_END.length <= message.length; start++) {
            if (Arrays.equals(message, start, start + HEAD_END.length, HEAD_END, 0, HEAD_END.length)) {
                return start;
            }
        }
        return message.length;
    }

    private static boolean isInterim(byte[] read, int start) {
        String status = statusCode(read, start);
        return status.startsWith("1") && !status.equals(SWITCHING_PROTOCOLS);
    }

    private static String statusCode(byte[] read, int start) {
        int codeStart = start + STATUS_CODE_OFFSET;
        return codeStart + STATUS_CODE_LENGTH <= read.length
                ? new String(read, codeStart, STATUS_CODE_LENGTH, StandardCharsets.ISO_8859_1) : "";
    }
}
