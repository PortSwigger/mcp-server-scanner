package com.mcpscanner.testutil;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.ServerSocket;

public final class OwnedLoopbackPort implements AutoCloseable {

    private final ServerSocket listener;

    private OwnedLoopbackPort(ServerSocket listener) {
        this.listener = listener;
    }

    public static OwnedLoopbackPort closingEveryConnection() {
        try {
            ServerSocket listener = new ServerSocket();
            listener.bind(new InetSocketAddress(InetAddress.getLoopbackAddress(), 0));
            OwnedLoopbackPort port = new OwnedLoopbackPort(listener);
            Thread acceptor = new Thread(port::closeEachAcceptedConnection, "owned-loopback-port");
            acceptor.setDaemon(true);
            acceptor.start();
            return port;
        } catch (IOException failed) {
            throw new UncheckedIOException(failed);
        }
    }

    public String url(String path) {
        return "http://127.0.0.1:" + listener.getLocalPort() + path;
    }

    private void closeEachAcceptedConnection() {
        while (!listener.isClosed()) {
            try {
                listener.accept().close();
            } catch (IOException closedListener) {
                return;
            }
        }
    }

    @Override
    public void close() throws IOException {
        listener.close();
    }
}
