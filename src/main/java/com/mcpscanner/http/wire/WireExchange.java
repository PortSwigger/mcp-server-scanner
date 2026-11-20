package com.mcpscanner.http.wire;

import com.mcpscanner.http.evidence.WireRecord;

import java.io.IOException;
import java.net.Socket;

public final class WireExchange implements AutoCloseable {

    private final Socket socket;
    private final WireResponse response;
    private final SocketTap tap;

    WireExchange(Socket socket, WireResponse response, SocketTap tap) {
        this.socket = socket;
        this.response = response;
        this.tap = tap;
    }

    public WireResponse response() {
        return response;
    }

    public WireRecord record() {
        return tap.record();
    }

    @Override
    public void close() throws IOException {
        socket.close();
    }
}
