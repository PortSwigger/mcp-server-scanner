package com.mcpscanner.cvetargets.burp;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.UncheckedIOException;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.SocketTimeoutException;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.atomic.AtomicInteger;

final class IdleClosingOrigin implements AutoCloseable {

    static final Duration IDLE_TIMEOUT = Duration.ofSeconds(2);

    private static final byte[] REPLY = ("HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: keep-alive\r\n\r\nok")
            .getBytes(StandardCharsets.US_ASCII);

    private final ServerSocket listener;
    private final ExecutorService connections = Executors.newCachedThreadPool();
    private final AtomicInteger idleClosed = new AtomicInteger();

    private IdleClosingOrigin(ServerSocket listener) {
        this.listener = listener;
    }

    static IdleClosingOrigin start() {
        try {
            IdleClosingOrigin origin = new IdleClosingOrigin(new ServerSocket(0, 128, InetAddress.getLoopbackAddress()));
            origin.connections.submit(origin::accept);
            return origin;
        } catch (IOException bindFailure) {
            throw new UncheckedIOException(bindFailure);
        }
    }

    String url() {
        return "http://127.0.0.1:" + listener.getLocalPort() + "/";
    }

    int idleClosed() {
        return idleClosed.get();
    }

    private void accept() {
        while (!listener.isClosed()) {
            try {
                Socket connection = listener.accept();
                connections.submit(() -> serve(connection));
            } catch (IOException closed) {
                return;
            }
        }
    }

    private void serve(Socket connection) {
        try (connection) {
            connection.setSoTimeout((int) IDLE_TIMEOUT.toMillis());
            InputStream in = connection.getInputStream();
            OutputStream out = connection.getOutputStream();
            while (readHead(in)) {
                out.write(REPLY);
                out.flush();
            }
        } catch (SocketTimeoutException idle) {
            idleClosed.incrementAndGet();
        } catch (IOException clientGone) {
            return;
        }
    }

    private static boolean readHead(InputStream in) throws IOException {
        int matched = 0;
        while (matched < 4) {
            int next = in.read();
            if (next < 0) {
                return false;
            }
            matched = (next == '\r' && matched % 2 == 0) || (next == '\n' && matched % 2 == 1) ? matched + 1 : 0;
        }
        return true;
    }

    @Override
    public void close() {
        try {
            listener.close();
        } catch (IOException ignored) {
        } finally {
            connections.shutdownNow();
        }
    }
}
