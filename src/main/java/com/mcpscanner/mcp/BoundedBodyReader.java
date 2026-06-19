package com.mcpscanner.mcp;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;

public final class BoundedBodyReader {

    public static final int MAX_RESPONSE_BYTES = 8 * 1024 * 1024;
    private static final int READ_CHUNK_BYTES = 8 * 1024;

    private BoundedBodyReader() {
    }

    public static String readUtf8(InputStream body) throws IOException {
        ByteArrayOutputStream buffer = new ByteArrayOutputStream();
        byte[] chunk = new byte[READ_CHUNK_BYTES];
        int totalRead = 0;
        int n;
        while ((n = body.read(chunk)) != -1) {
            totalRead += n;
            if (totalRead > MAX_RESPONSE_BYTES) {
                throw new IOException("Upstream response exceeded " + MAX_RESPONSE_BYTES + " bytes");
            }
            buffer.write(chunk, 0, n);
        }
        return buffer.toString(StandardCharsets.UTF_8);
    }
}
