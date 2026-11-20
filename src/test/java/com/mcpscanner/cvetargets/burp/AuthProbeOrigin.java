package com.mcpscanner.cvetargets.burp;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.UncheckedIOException;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.Queue;
import java.util.concurrent.ConcurrentLinkedQueue;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;

final class AuthProbeOrigin implements AutoCloseable {

    static final Duration HELD_OPEN = Duration.ofSeconds(30);

    private static final String BEARER_CHALLENGE = """
            HTTP/1.1 401 Unauthorized\r
            WWW-Authenticate: Bearer realm="mcp"\r
            Content-Length: 0\r
            Connection: close\r
            \r
            """;
    private static final String STREAM_HEADERS_AND_PING = """
            HTTP/1.1 200 OK\r
            Content-Type: text/event-stream\r
            Cache-Control: no-cache\r
            Transfer-Encoding: chunked\r
            \r
            8\r
            : ping

            \r
            """;
    private static final byte[] END_OF_HEADERS = "\r\n\r\n".getBytes(StandardCharsets.US_ASCII);

    private final ServerSocket listener;
    private final Behaviour behaviour;
    private final ExecutorService connections = Executors.newCachedThreadPool(AuthProbeOrigin::daemon);
    private final Queue<Socket> accepted = new ConcurrentLinkedQueue<>();
    private final CountDownLatch closed = new CountDownLatch(1);

    private AuthProbeOrigin(ServerSocket listener, Behaviour behaviour) {
        this.listener = listener;
        this.behaviour = behaviour;
        connections.submit(this::acceptUntilClosed);
    }

    static AuthProbeOrigin bearerChallenge() {
        return start((origin, socket) -> origin.reply(socket, BEARER_CHALLENGE));
    }

    static AuthProbeOrigin heldOpenEventStream() {
        return start((origin, socket) -> {
            origin.reply(socket, STREAM_HEADERS_AND_PING);
            origin.holdOpen();
        });
    }

    static AuthProbeOrigin silent() {
        return start((origin, socket) -> origin.holdOpen());
    }

    private static AuthProbeOrigin start(Behaviour behaviour) {
        try {
            return new AuthProbeOrigin(new ServerSocket(0, 50, InetAddress.getLoopbackAddress()), behaviour);
        } catch (IOException bindFailure) {
            throw new UncheckedIOException(bindFailure);
        }
    }

    String url() {
        return "http://127.0.0.1:" + listener.getLocalPort() + "/mcp";
    }

    private void acceptUntilClosed() {
        while (!listener.isClosed()) {
            try {
                Socket socket = listener.accept();
                accepted.add(socket);
                connections.submit(() -> serve(socket));
            } catch (IOException listenerClosed) {
                return;
            }
        }
    }

    private void serve(Socket socket) {
        try (socket) {
            behaviour.serve(this, socket);
        } catch (IOException clientGone) {
            return;
        }
    }

    private void reply(Socket socket, String response) throws IOException {
        readRequestHeaders(socket.getInputStream());
        OutputStream out = socket.getOutputStream();
        out.write(response.getBytes(StandardCharsets.US_ASCII));
        out.flush();
    }

    private void holdOpen() {
        try {
            closed.await(HELD_OPEN.toMillis(), TimeUnit.MILLISECONDS);
        } catch (InterruptedException interrupted) {
            Thread.currentThread().interrupt();
        }
    }

    private static void readRequestHeaders(InputStream in) throws IOException {
        int matched = 0;
        while (matched < END_OF_HEADERS.length) {
            int next = in.read();
            if (next < 0) {
                throw new IOException("request ended before its headers");
            }
            matched = next == END_OF_HEADERS[matched] ? matched + 1 : (next == END_OF_HEADERS[0] ? 1 : 0);
        }
    }

    @Override
    public void close() {
        closed.countDown();
        try {
            listener.close();
        } catch (IOException ignored) {
            // closing anyway
        }
        accepted.forEach(AuthProbeOrigin::closeQuietly);
        connections.shutdownNow();
    }

    private static void closeQuietly(Socket socket) {
        try {
            socket.close();
        } catch (IOException ignored) {
            // closing anyway
        }
    }

    private static Thread daemon(Runnable runnable) {
        Thread thread = new Thread(runnable, "auth-probe-origin");
        thread.setDaemon(true);
        return thread;
    }

    @FunctionalInterface
    private interface Behaviour {
        void serve(AuthProbeOrigin origin, Socket socket) throws IOException;
    }
}
