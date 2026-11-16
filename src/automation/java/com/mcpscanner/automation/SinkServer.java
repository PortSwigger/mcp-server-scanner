package com.mcpscanner.automation;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.UncheckedIOException;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.util.Locale;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public final class SinkServer implements AutoCloseable {

    private static final int WORKERS = 16;
    private static final int READ_TIMEOUT_MILLIS = 2000;
    private static final int HEADER_LIMIT = 64 * 1024;
    private static final int BODY_LIMIT = 1024 * 1024;
    private static final Pattern CONTENT_LENGTH = Pattern.compile("(?m)^content-length:\\s*(\\d{1,9})\\s*$");
    private static final byte[] REPLY = ("HTTP/1.1 404 Not Found\r\n" + SinkReply.HEADER + ": built-in\r\n"
            + "Content-Length: 0\r\nConnection: close\r\n\r\n").getBytes(StandardCharsets.ISO_8859_1);

    private final ServerSocket socket;
    private final ExecutorService workers = Executors.newFixedThreadPool(WORKERS, runnable -> {
        Thread thread = new Thread(runnable, "mcp-test-automation-sink");
        thread.setDaemon(true);
        return thread;
    });

    private SinkServer(ServerSocket socket) {
        this.socket = socket;
    }

    public static SinkServer start() {
        try {
            SinkServer server = new SinkServer(new ServerSocket(0, 128, InetAddress.getLoopbackAddress()));
            server.workers.execute(server::acceptUntilClosed);
            return server;
        } catch (IOException bindFailure) {
            throw new UncheckedIOException(bindFailure);
        }
    }

    public int port() {
        return socket.getLocalPort();
    }

    InetSocketAddress address() {
        return (InetSocketAddress) socket.getLocalSocketAddress();
    }

    @Override
    public void close() {
        try {
            socket.close();
        } catch (IOException ignored) {
        } finally {
            workers.shutdownNow();
        }
    }

    private void acceptUntilClosed() {
        while (!socket.isClosed()) {
            try {
                Socket connection = socket.accept();
                workers.execute(() -> answer(connection));
            } catch (IOException closed) {
                return;
            }
        }
    }

    private static void answer(Socket connection) {
        try (connection) {
            connection.setSoTimeout(READ_TIMEOUT_MILLIS);
            InputStream in = connection.getInputStream();
            String head = readHead(in);
            discard(in, contentLength(head));
            OutputStream out = connection.getOutputStream();
            out.write(REPLY);
            out.flush();
        } catch (IOException ignored) {
        }
    }

    private static String readHead(InputStream in) throws IOException {
        StringBuilder head = new StringBuilder();
        int matched = 0;
        while (head.length() < HEADER_LIMIT && matched < 4) {
            int next = in.read();
            if (next < 0) {
                break;
            }
            head.append((char) next);
            matched = (next == '\r' && matched % 2 == 0) || (next == '\n' && matched % 2 == 1) ? matched + 1 : 0;
        }
        return head.toString();
    }

    private static int contentLength(String head) {
        Matcher matcher = CONTENT_LENGTH.matcher(head.toLowerCase(Locale.ROOT).replace("\r", ""));
        return matcher.find() ? (int) Math.min(Long.parseLong(matcher.group(1)), BODY_LIMIT) : 0;
    }

    private static void discard(InputStream in, int length) throws IOException {
        in.readNBytes(length);
    }
}
