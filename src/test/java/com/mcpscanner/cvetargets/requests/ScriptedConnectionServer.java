package com.mcpscanner.cvetargets.requests;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

final class ScriptedConnectionServer implements AutoCloseable {

    @FunctionalInterface
    interface Reply {
        void write(OutputStream out, CountDownLatch serverClosed) throws IOException, InterruptedException;
    }

    static final Reply DROP = (out, serverClosed) -> { };
    static final Reply UNTIL_CLOSED = (out, serverClosed) -> serverClosed.await();

    private final ServerSocket socket = new ServerSocket(0, 50, InetAddress.getLoopbackAddress());
    private final List<Reply> repliesByConnection;
    private final AtomicInteger connections = new AtomicInteger();
    private final CountDownLatch closed = new CountDownLatch(1);

    ScriptedConnectionServer(List<Reply> repliesByConnection) throws IOException {
        this.repliesByConnection = List.copyOf(repliesByConnection);
        Thread acceptor = new Thread(this::acceptConnections);
        acceptor.setDaemon(true);
        acceptor.start();
    }

    static Reply raw(String response) {
        return (out, serverClosed) -> out.write(response.getBytes(StandardCharsets.ISO_8859_1));
    }

    static Reply truncated(String partialResponse) {
        return (out, serverClosed) -> {
            raw(partialResponse).write(out, serverClosed);
            out.close();
        };
    }

    static Reply after(long millis, Reply reply) {
        return (out, serverClosed) -> {
            serverClosed.await(millis, TimeUnit.MILLISECONDS);
            reply.write(out, serverClosed);
        };
    }

    String url(String path) {
        return "http://127.0.0.1:" + socket.getLocalPort() + path;
    }

    int connectionCount() {
        return connections.get();
    }

    @Override
    public void close() throws IOException {
        closed.countDown();
        socket.close();
    }

    private void acceptConnections() {
        while (!socket.isClosed()) {
            try {
                Socket connection = socket.accept();
                Reply reply = repliesByConnection.get(
                        Math.min(connections.getAndIncrement(), repliesByConnection.size() - 1));
                Thread worker = new Thread(() -> serve(connection, reply, closed));
                worker.setDaemon(true);
                worker.start();
            } catch (IOException closed) {
                return;
            }
        }
    }

    private static void serve(Socket connection, Reply reply, CountDownLatch closed) {
        try (connection) {
            BufferedReader reader = new BufferedReader(
                    new InputStreamReader(connection.getInputStream(), StandardCharsets.ISO_8859_1));
            String line;
            while ((line = reader.readLine()) != null && !line.isEmpty()) {
                continue;
            }
            reply.write(connection.getOutputStream(), closed);
            connection.getOutputStream().flush();
            if (reply != DROP) {
                connection.getInputStream().read();
            }
        } catch (IOException | InterruptedException ended) {
            return;
        }
    }
}
