package com.mcpscanner.http.evidence;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.Locale;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.TimeUnit;

final class LoopbackWireCapture implements AutoCloseable {

    private static final byte[] HEAD_END = "\r\n\r\n".getBytes(StandardCharsets.ISO_8859_1);

    private final ServerSocket server;
    private final HttpClient client = HttpClient.newBuilder()
            .version(HttpClient.Version.HTTP_1_1)
            .connectTimeout(Duration.ofSeconds(10))
            .followRedirects(HttpClient.Redirect.NEVER)
            .build();

    LoopbackWireCapture() throws IOException {
        server = new ServerSocket(0, 50, InetAddress.getLoopbackAddress());
        server.setSoTimeout(10_000);
    }

    URI uri(String pathAndQuery) {
        return URI.create("http://127.0.0.1:" + server.getLocalPort() + pathAndQuery);
    }

    Captured send(HttpRequest request, String reply) throws Exception {
        CompletableFuture<HttpResponse<byte[]>> pending = client.sendAsync(request,
                HttpResponse.BodyHandlers.ofByteArray());
        byte[] received;
        try (Socket accepted = server.accept()) {
            accepted.setSoTimeout(10_000);
            received = readRequest(accepted.getInputStream());
            accepted.getOutputStream().write(reply.getBytes(StandardCharsets.ISO_8859_1));
            accepted.getOutputStream().flush();
        }
        return new Captured(received, pending.get(10, TimeUnit.SECONDS));
    }

    @Override
    public void close() throws IOException {
        server.close();
    }

    private static byte[] readRequest(InputStream in) throws IOException {
        ByteArrayOutputStream read = new ByteArrayOutputStream();
        while (indexOf(read.toByteArray(), HEAD_END) < 0) {
            int next = in.read();
            if (next < 0) {
                return read.toByteArray();
            }
            read.write(next);
        }
        read.write(in.readNBytes(contentLength(read.toString(StandardCharsets.ISO_8859_1))));
        return read.toByteArray();
    }

    private static int contentLength(String head) {
        return head.lines()
                .filter(line -> line.toLowerCase(Locale.ROOT).startsWith("content-length:"))
                .map(line -> Integer.parseInt(line.substring(line.indexOf(':') + 1).trim()))
                .findFirst().orElse(0);
    }

    private static int indexOf(byte[] haystack, byte[] needle) {
        for (int start = 0; start + needle.length <= haystack.length; start++) {
            if (java.util.Arrays.equals(haystack, start, start + needle.length, needle, 0, needle.length)) {
                return start;
            }
        }
        return -1;
    }

    record Captured(byte[] received, HttpResponse<byte[]> response) {

        String receivedText() {
            return new String(received, StandardCharsets.ISO_8859_1);
        }
    }
}
