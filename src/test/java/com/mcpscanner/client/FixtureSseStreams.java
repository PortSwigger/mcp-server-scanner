package com.mcpscanner.client;

import com.sun.net.httpserver.HttpExchange;

import java.io.IOException;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicInteger;

public final class FixtureSseStreams implements AutoCloseable {
    private final Map<String, OutputStream> streams = new ConcurrentHashMap<>();
    private final AtomicInteger ids = new AtomicInteger();

    public String open(HttpExchange exchange) throws IOException {
        exchange.getResponseHeaders().set("Content-Type", "text/event-stream");
        exchange.sendResponseHeaders(200, 0);
        String id = Integer.toString(ids.incrementAndGet());
        streams.put(id, exchange.getResponseBody());
        return id;
    }

    public void send(String streamId, String event, String data) throws IOException {
        OutputStream stream = streams.get(streamId);
        if (stream == null) {
            throw new IOException("Unknown SSE stream " + streamId);
        }
        synchronized (stream) {
            stream.write(("event: " + event + "\ndata: " + data + "\n\n").getBytes(StandardCharsets.UTF_8));
            stream.flush();
        }
    }

    void broadcast(String event, String data) throws IOException {
        for (String streamId : streams.keySet()) {
            send(streamId, event, data);
        }
    }

    public void close(String streamId) {
        OutputStream stream = streams.remove(streamId);
        if (stream != null) {
            closeQuietly(stream);
        }
    }

    @Override
    public void close() {
        streams.values().forEach(FixtureSseStreams::closeQuietly);
        streams.clear();
    }

    private static void closeQuietly(OutputStream stream) {
        try {
            stream.close();
        } catch (IOException alreadyClosed) {
            return;
        }
    }
}
