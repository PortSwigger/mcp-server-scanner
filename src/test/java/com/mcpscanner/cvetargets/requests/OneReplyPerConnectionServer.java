package com.mcpscanner.cvetargets.requests;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.util.Locale;

final class OneReplyPerConnectionServer implements AutoCloseable {

    private static final String KEPT_ALIVE_REPLY = "HTTP/1.1 200 OK\r\nConnection: keep-alive\r\n"
            + "Content-Type: application/json\r\nContent-Length: 2\r\n\r\n{}";
    private static final String REUSED_CONNECTION_REPLY = "HTTP/1.1 400 Bad Request\r\nConnection: close\r\n"
            + "Content-Length: 0\r\n\r\n";

    private final ServerSocket socket = new ServerSocket(0, 50, InetAddress.getLoopbackAddress());
    private final Thread acceptor = new Thread(this::acceptConnections);

    OneReplyPerConnectionServer() throws IOException {
        acceptor.setDaemon(true);
        acceptor.start();
    }

    int port() {
        return socket.getLocalPort();
    }

    @Override
    public void close() throws IOException {
        socket.close();
    }

    private void acceptConnections() {
        while (!socket.isClosed()) {
            try {
                Socket connection = socket.accept();
                Thread worker = new Thread(() -> serve(connection));
                worker.setDaemon(true);
                worker.start();
            } catch (IOException closed) {
                return;
            }
        }
    }

    private static void serve(Socket connection) {
        try (connection) {
            BufferedReader reader = new BufferedReader(
                    new InputStreamReader(connection.getInputStream(), StandardCharsets.ISO_8859_1));
            OutputStream out = connection.getOutputStream();
            String reply = KEPT_ALIVE_REPLY;
            while (readRequest(reader)) {
                out.write(reply.getBytes(StandardCharsets.ISO_8859_1));
                out.flush();
                reply = REUSED_CONNECTION_REPLY;
            }
        } catch (IOException dropped) {
            return;
        }
    }

    private static boolean readRequest(BufferedReader reader) throws IOException {
        String line = reader.readLine();
        if (line == null) {
            return false;
        }
        int contentLength = 0;
        while ((line = reader.readLine()) != null && !line.isEmpty()) {
            if (line.toLowerCase(Locale.ROOT).startsWith("content-length:")) {
                contentLength = Integer.parseInt(line.substring(15).trim());
            }
        }
        reader.skip(contentLength);
        return true;
    }
}
